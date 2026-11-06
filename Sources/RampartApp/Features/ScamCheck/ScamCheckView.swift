import SwiftUI
import AppKit
import UniformTypeIdentifiers
import RampartShared
import RampartWeb

// "Scam Check" screen (W1). Paste a message, link or email, or drop a .eml file; get an
// explainable verdict with the risky phrases and links highlighted. The AI second opinion is a
// closure on ScamCheckModel that the AI agent wires up (`ScamCheckModel.aiAssessor`).

@MainActor
@Observable
final class ScamCheckModel {
    /// Set by the AI module at app start: `ScamCheckModel.aiAssessor = GeminiScamAssessor()`.
    nonisolated(unsafe) static var aiAssessor: (any ScamAIAssessor)? = nil

    var input = ""
    var report: ScamReport? = nil
    var isChecking = false
    var isAskingAI = false
    var aiError: String? = nil
    var droppedFileName: String? = nil
    var history: [ScamReport] = []

    let checker = ScamChecker(urls: URLAnalyzer(seenDomains: FileSeenDomainStore(), allowlist: FileWebAllowlist()))

    var canCheck: Bool { !input.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && !isChecking }
    var aiAvailable: Bool { ScamCheckModel.aiAssessor?.isConfigured ?? false }

    func check() {
        let text = input
        guard !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return }
        isChecking = true; aiError = nil
        let checker = self.checker
        Task.detached(priority: .userInitiated) {
            let r = checker.check(text)
            await MainActor.run {
                withAnimation(.spring(response: 0.45, dampingFraction: 0.85)) { self.report = r }
                self.history.insert(r, at: 0); if self.history.count > 20 { self.history.removeLast() }
                self.isChecking = false
            }
        }
    }

    func clear() { withAnimation { report = nil; input = ""; droppedFileName = nil; aiError = nil } }

    func askAI() {
        guard let assessor = ScamCheckModel.aiAssessor, let r = report else { return }
        isAskingAI = true; aiError = nil
        let text = input
        Task {
            do {
                let updated = try await checker.withAI(r, input: text, assessor: assessor)
                withAnimation { report = updated }
            } catch { aiError = "The AI second opinion isn't available right now: \(error.localizedDescription)" }
            isAskingAI = false
        }
    }

    /// Accepts dropped .eml / .txt files (and plain text drags).
    func handleDrop(_ providers: [NSItemProvider]) -> Bool {
        for p in providers {
            if p.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier) {
                p.loadItem(forTypeIdentifier: UTType.fileURL.identifier) { item, _ in
                    guard let data = item as? Data, let url = URL(dataRepresentation: data, relativeTo: nil) else { return }
                    guard let d = try? Data(contentsOf: url), d.count < 4 * 1024 * 1024 else { return }
                    let text = String(data: d, encoding: .utf8) ?? String(data: d, encoding: .isoLatin1) ?? ""
                    Task { @MainActor in self.droppedFileName = url.lastPathComponent; self.input = text; self.check() }
                }
                return true
            }
            if p.hasItemConformingToTypeIdentifier(UTType.plainText.identifier) {
                p.loadItem(forTypeIdentifier: UTType.plainText.identifier) { item, _ in
                    let text = (item as? String) ?? (item as? Data).flatMap { String(data: $0, encoding: .utf8) } ?? ""
                    guard !text.isEmpty else { return }
                    Task { @MainActor in self.droppedFileName = nil; self.input = text; self.check() }
                }
                return true
            }
        }
        return false
    }
}

struct ScamCheckView: View {
    @StateVar private var model = ScamCheckModel()
    @StateVar private var dropTargeted = false
    @StateVar private var showExamples = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Spacing.xl) {
                header
                inputCard
                if let r = model.report { VerdictCard(report: r, model: model).transition(reduceMotion ? .opacity : .move(edge: .bottom).combined(with: .opacity)) }
                if let r = model.report, !r.urls.isEmpty { LinksCard(urls: r.urls) }
                tipsCard
                honestyNote
            }
            .contentColumn()
        }
        .navigationTitle("Scam Check")
        .onDrop(of: [.fileURL, .plainText], isTargeted: $dropTargeted) { model.handleDrop($0) }
    }

    private var header: some View {
        HStack(spacing: Spacing.l) {
            IconBadge(symbol: "text.magnifyingglass", tint: .rampartTeal, size: 52)
            VStack(alignment: .leading, spacing: 3) {
                Text("Is this a scam?").font(.title2.weight(.bold)).fontDesign(.rounded)
                Text("Paste a text message, email, chat message or link. RamPart checks it on your Mac, explains what it found, and nothing leaves your computer unless you ask for an AI opinion.")
                    .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
        }
    }

    private var inputCard: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            ZStack(alignment: .topLeading) {
                TextEditor(text: Binding(get: { model.input }, set: { model.input = $0 }))
                    .font(.body.monospaced())
                    .scrollContentBackground(.hidden)
                    .frame(minHeight: 170, maxHeight: 320)
                    .padding(Spacing.s)
                    .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(Color.primary.opacity(0.04)))
                    .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(dropTargeted ? Color.rampartTeal : Color.primary.opacity(0.08), lineWidth: dropTargeted ? 2 : 1))
                    .accessibilityLabel("Message, link or email to check")
                if model.input.isEmpty {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Paste a message, link or email").font(.title3.weight(.medium)).foregroundStyle(.secondary)
                        Text("…or drop a .eml file here. Raw email headers work too.").font(.callout).foregroundStyle(.tertiary)
                    }
                    .padding(Spacing.l).allowsHitTesting(false)
                }
            }
            HStack(spacing: Spacing.m) {
                Button { model.check() } label: { Label(model.isChecking ? "Checking…" : "Check", systemImage: "checkmark.shield") }
                    .buttonStyle(GlowButtonStyle()).controlSize(.large).disabled(!model.canCheck).keyboardShortcut(.return, modifiers: .command)
                Button("Paste & check") {
                    // Reads the pasteboard only when the user clicks: never automatically.
                    if let s = NSPasteboard.general.string(forType: .string), !s.isEmpty { model.input = s; model.droppedFileName = nil; model.check() }
                }.secondaryActionStyle()
                Button("Clear") { model.clear() }.secondaryActionStyle().disabled(model.input.isEmpty && model.report == nil)
                Spacer()
                if let f = model.droppedFileName { Label(f, systemImage: "envelope").font(.callout).foregroundStyle(.secondary) }
                Menu("Try an example") {
                    ForEach(ScamCheckExamples.all, id: \.title) { ex in Button(ex.title) { model.input = ex.text; model.droppedFileName = nil; model.check() } }
                }.menuStyle(.borderlessButton).fixedSize()
            }
            Text("⌘↩ to check. Private by design: the check runs offline on this Mac.").font(.caption).foregroundStyle(.tertiary)
        }
        .card()
    }

    private var tipsCard: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            SectionHeader("Three questions that stop most scams")
            TipRow(symbol: "clock.badge.exclamationmark", title: "Is it rushing you?", text: "Deadlines, threats and “act now” exist to stop you thinking. Real organisations give you time.")
            TipRow(symbol: "giftcard", title: "Is it asking for an odd way to pay?", text: "Gift cards, crypto, wire transfers and “refund” screen-shares are never how bills, fines or support work.")
            TipRow(symbol: "link", title: "Did you go there yourself?", text: "Don't use the link in the message. Open the company's app or type its address, then check.")
        }
        .card()
    }

    private var honestyNote: some View {
        HStack(alignment: .top, spacing: Spacing.m) {
            Image(systemName: "info.circle").foregroundStyle(.secondary)
            Text("Scam Check looks for known patterns and look-alike addresses. It can miss a new scam and can be wrong about an unusual but genuine message. Treat “Likely safe” as “no red flags found”, not as a guarantee.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
    }
}

private struct TipRow: View {
    let symbol: String, title: String, text: String
    var body: some View {
        HStack(alignment: .top, spacing: Spacing.m) {
            IconBadge(symbol: symbol, tint: .rampartTeal, size: 30)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.body.weight(.medium))
                Text(text).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

// MARK: - Verdict card

struct VerdictCard: View {
    let report: ScamReport
    let model: ScamCheckModel
    @StateVar private var appeared = false
    @StateVar private var showAll = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    private var tint: Color {
        switch report.verdict { case .likelySafe: return .statusProtected; case .suspicious: return .statusAttention; case .likelyScam: return .statusAction }
    }
    private var symbol: String {
        switch report.verdict { case .likelySafe: return "checkmark.shield.fill"; case .suspicious: return "exclamationmark.triangle.fill"; case .likelyScam: return "xmark.shield.fill" }
    }
    private var kindLabel: String {
        switch report.kind { case .message: return "Message"; case .url: return "Link"; case .email: return "Email"; case .page: return "Web page" }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.l) {
            HStack(alignment: .top, spacing: Spacing.l) {
                ZStack {
                    Circle().fill(tint.opacity(0.15)).frame(width: 72, height: 72)
                    Circle().strokeBorder(tint.opacity(0.35), lineWidth: 1).frame(width: 72, height: 72)
                    Image(systemName: symbol).font(.system(size: 34, weight: .semibold)).symbolRenderingMode(.hierarchical).foregroundStyle(tint)
                        .scaleEffect(appeared || reduceMotion ? 1 : 0.6)
                }
                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: Spacing.s) {
                        Text(report.verdict.title).font(.title.weight(.bold)).fontDesign(.rounded).foregroundStyle(tint)
                        Badge(text: kindLabel)
                        if report.language != "en" { Badge(text: report.language.uppercased()) }
                    }
                    Text(report.headline).font(.body).fixedSize(horizontal: false, vertical: true)
                }
                Spacer()
                RiskGauge(score: report.score, tint: tint, animate: appeared && !reduceMotion)
            }
            if !report.signals.filter({ $0.score > 0 }).isEmpty || report.aiOpinion != nil {
                Divider()
            }
            let shown = report.signals.filter { $0.score > 0 }
            if !shown.isEmpty {
                Text("Why").font(.headline)
                ForEach(Array((showAll ? shown : Array(shown.prefix(5))).enumerated()), id: \.element.id) { i, s in
                    SignalRow(signal: s).transition(.opacity)
                        .opacity(appeared || reduceMotion ? 1 : 0)
                        .animation(reduceMotion ? nil : .easeOut(duration: 0.3).delay(0.08 * Double(i)), value: appeared)
                }
                if shown.count > 5 {
                    Button(showAll ? "Show fewer" : "Show all \(shown.count) findings") { withAnimation { showAll.toggle() } }.buttonStyle(.link)
                }
            }
            let benign = report.signals.filter { $0.category == .benign }
            if !benign.isEmpty { ForEach(benign, id: \.id) { s in Label { Text(s.title).font(.callout) } icon: { Image(systemName: "checkmark.circle").foregroundStyle(Color.statusProtected) } } }

            if !report.analysedText.isEmpty && report.kind != .url {
                DisclosureGroup("Highlighted text") { HighlightedText(text: report.analysedText, highlights: report.highlights, tint: tint).padding(.top, Spacing.s) }
                    .font(.callout.weight(.medium))
            }

            Divider()
            HStack(spacing: Spacing.m) {
                Button { model.askAI() } label: {
                    Label(model.isAskingAI ? "Asking…" : "Ask AI for a second opinion", systemImage: "sparkles")
                }
                .secondaryActionStyle().disabled(!model.aiAvailable || model.isAskingAI || report.aiOpinion != nil)
                if !model.aiAvailable { Text("Add a Gemini key in Settings to enable").font(.caption).foregroundStyle(.secondary) }
                else if report.aiOpinion == nil { Text("Sends this text to the AI provider").font(.caption).foregroundStyle(.secondary) }
                Spacer()
                Button { copyReport() } label: { Label("Copy report", systemImage: "doc.on.doc") }.buttonStyle(.borderless)
            }
            if let e = model.aiError { Text(e).font(.caption).foregroundStyle(Color.statusAction) }
            if let ai = report.aiOpinion { AIOpinionView(opinion: ai) }
        }
        .card(tint: tint)
        .onAppear { withAnimation(reduceMotion ? nil : .spring(response: 0.5, dampingFraction: 0.7)) { appeared = true } }
        .accessibilityElement(children: .contain)
        .accessibilityLabel("\(report.verdict.title), risk \(report.score) out of 100. \(report.headline)")
    }

    private func copyReport() {
        var s = "RamPart Scam Check: \(report.verdict.title) (risk \(report.score)/100)\n\(report.headline)\n\n"
        for sig in report.signals where sig.score > 0 { s += "• \(sig.title): \(sig.explanation)\n" }
        if let ai = report.aiOpinion { s += "\nAI second opinion (\(ai.provider)): \(ai.verdict.title), \(ai.confidence)% — \(ai.summary)\n" }
        NSPasteboard.general.clearContents(); NSPasteboard.general.setString(s, forType: .string)
    }
}

struct RiskGauge: View {
    let score: Int, tint: Color, animate: Bool
    var body: some View {
        ZStack {
            Circle().stroke(Color.primary.opacity(0.08), lineWidth: 7)
            Circle().trim(from: 0, to: animate ? CGFloat(score) / 100 : 0)
                .stroke(AngularGradient(colors: [tint.opacity(0.6), tint], center: .center), style: StrokeStyle(lineWidth: 7, lineCap: .round))
                .rotationEffect(.degrees(-90))
                .animation(.easeOut(duration: 0.9), value: animate)
            VStack(spacing: 0) {
                Text("\(score)").font(.title3.weight(.bold)).fontDesign(.rounded).monospacedDigit()
                Text("risk").font(.caption2).foregroundStyle(.secondary)
            }
        }
        .frame(width: 68, height: 68)
        .accessibilityLabel("Risk score \(score) of 100")
    }
}

struct SignalRow: View {
    let signal: ScamSignal
    private var tint: Color { signal.score >= 70 ? .statusAction : signal.score >= 35 ? .statusAttention : .statusInfo }
    var body: some View {
        HStack(alignment: .top, spacing: Spacing.m) {
            Image(systemName: signal.score >= 70 ? "exclamationmark.octagon.fill" : signal.score >= 35 ? "exclamationmark.triangle.fill" : "info.circle.fill")
                .foregroundStyle(tint).symbolRenderingMode(.hierarchical).frame(width: 20)
            VStack(alignment: .leading, spacing: 3) {
                HStack { Text(signal.title).font(.body.weight(.medium)); Spacer(); Text("+\(signal.score)").font(.caption.monospacedDigit()).foregroundStyle(.tertiary) }
                Text(signal.explanation).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                if !signal.evidence.isEmpty {
                    FlowLayout(spacing: 6) {
                        ForEach(Array(signal.evidence.prefix(4).enumerated()), id: \.offset) { _, ev in
                            Text(ev.text.count > 70 ? String(ev.text.prefix(70)) + "…" : ev.text)
                                .font(.caption.monospaced()).lineLimit(1)
                                .padding(.horizontal, 6).padding(.vertical, 2)
                                .background(tint.opacity(0.14), in: RoundedRectangle(cornerRadius: 5, style: .continuous))
                        }
                    }
                }
            }
        }
        .accessibilityElement(children: .combine)
    }
}

struct AIOpinionView: View {
    let opinion: ScamAIOpinion
    private var tint: Color { switch opinion.verdict { case .likelySafe: return .statusProtected; case .suspicious: return .statusAttention; case .likelyScam: return .statusAction } }
    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.s) {
            HStack { Label("AI second opinion · \(opinion.provider)", systemImage: "sparkles").font(.headline); Spacer(); Text(opinion.verdict.title).font(.callout.weight(.semibold)).foregroundStyle(tint); Text("\(opinion.confidence)%").font(.caption.monospacedDigit()).foregroundStyle(.secondary) }
            Text(opinion.summary).font(.callout).fixedSize(horizontal: false, vertical: true)
            ForEach(opinion.reasons, id: \.self) { r in Label { Text(r).font(.callout).foregroundStyle(.secondary) } icon: { Image(systemName: "circle.fill").font(.system(size: 5)).foregroundStyle(.secondary) } }
            Text("AI opinions can be wrong. RamPart's offline verdict above stays the primary result.").font(.caption).foregroundStyle(.tertiary)
        }
        .padding(Spacing.m)
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(tint.opacity(0.07)))
    }
}

/// Renders the analysed text with highlighted spans (offsets are UTF-16, as produced by the engine).
struct HighlightedText: View {
    let text: String, highlights: [ScamHighlight], tint: Color
    var body: some View {
        ScrollView { Text(attributed).font(.callout).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) }
            .frame(maxHeight: 260)
            .padding(Spacing.m)
            .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(Color.primary.opacity(0.04)))
    }
    private var attributed: AttributedString {
        var a = AttributedString(text)
        let ns = text as NSString
        for h in highlights {
            if let s = h.start, let e = h.end, s >= 0, e <= ns.length, e > s, let lo = AttributedString.Index(String.Index(utf16Offset: s, in: text), within: a), let hi = AttributedString.Index(String.Index(utf16Offset: e, in: text), within: a) {
                a[lo..<hi].backgroundColor = tint.opacity(0.28); a[lo..<hi].font = .callout.weight(.semibold)
            } else if !h.text.isEmpty {
                var searchRange = text.startIndex..<text.endIndex
                var n = 0
                while let r = text.range(of: h.text, options: [.caseInsensitive], range: searchRange), n < 5 {
                    if let lo = AttributedString.Index(r.lowerBound, within: a), let hi = AttributedString.Index(r.upperBound, within: a) {
                        a[lo..<hi].backgroundColor = (h.kind == .link || h.kind == .domain ? Color.rampartTeal : tint).opacity(0.28); a[lo..<hi].font = .callout.weight(.semibold)
                    }
                    searchRange = r.upperBound..<text.endIndex; n += 1
                }
            }
        }
        return a
    }
}

struct LinksCard: View {
    let urls: [URLReport]
    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            SectionHeader("Links found")
            ForEach(Array(urls.enumerated()), id: \.offset) { _, u in
                let tint: Color = u.verdict == .likelyScam ? .statusAction : u.verdict == .suspicious ? .statusAttention : .statusProtected
                HStack(alignment: .top, spacing: Spacing.m) {
                    Image(systemName: u.verdict == .likelySafe ? "link" : "link.badge.plus").foregroundStyle(tint).frame(width: 20)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(u.host ?? u.original).font(.body.weight(.medium)).textSelection(.enabled)
                        if let b = u.brandMatch { Text("Pretends to be \(b)").font(.callout).foregroundStyle(tint) }
                        Text(u.original).font(.caption.monospaced()).foregroundStyle(.secondary).lineLimit(2).textSelection(.enabled)
                        if let top = u.signals.first, top.score > 0 { Text(top.explanation).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true) }
                    }
                    Spacer()
                    Badge(text: u.verdict.title, tint: tint)
                }
            }
            Text("Links aren't opened. Only the address is examined.").font(.caption).foregroundStyle(.tertiary)
        }
        .card()
    }
}

/// Simple wrapping layout for evidence chips.
struct FlowLayout: Layout {
    var spacing: CGFloat = 6
    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let w = proposal.width ?? 400
        var x: CGFloat = 0, y: CGFloat = 0, rowH: CGFloat = 0
        for s in subviews {
            let sz = s.sizeThatFits(.unspecified)
            if x + sz.width > w, x > 0 { x = 0; y += rowH + spacing; rowH = 0 }
            x += sz.width + spacing; rowH = max(rowH, sz.height)
        }
        return CGSize(width: w, height: y + rowH)
    }
    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var x = bounds.minX, y = bounds.minY, rowH: CGFloat = 0
        for s in subviews {
            let sz = s.sizeThatFits(.unspecified)
            if x + sz.width > bounds.maxX, x > bounds.minX { x = bounds.minX; y += rowH + spacing; rowH = 0 }
            s.place(at: CGPoint(x: x, y: y), proposal: ProposedViewSize(sz))
            x += sz.width + spacing; rowH = max(rowH, sz.height)
        }
    }
}

/// Synthetic examples (no real people, numbers or sites) for the "Try an example" menu.
enum ScamCheckExamples {
    struct Example { let title: String; let text: String }
    static let all: [Example] = [
        Example(title: "Delivery text", text: "Your package could not be delivered due to an incomplete address. Pay the $1.99 redelivery fee here: https://usps-redelivery.test/track"),
        Example(title: "Fake Apple alert", text: "APPLE SECURITY ALERT! Your Mac is infected with 3 viruses. Do not shut down your computer. Call Apple Support now at (555) 010-0199."),
        Example(title: "Look-alike link", text: "https://xn--pypal-4ve.test/signin"),
        Example(title: "Family emergency", text: "Hi Mum, this is my new number, my phone fell in the sink. Can you transfer £850 for a bill today? I'll pay you back on Friday xx"),
        Example(title: "Ordinary message", text: "Hey, are we still on for lunch tomorrow at 12:30? I was thinking the Thai place near the office."),
    ]
}
