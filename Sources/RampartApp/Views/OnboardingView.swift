import SwiftUI
import RampartShared
import AppKit
import Combine

struct OnboardingView: View {
    enum Step: Int, CaseIterable { case welcome, permissions, firstScan }
    var onFinish: () -> Void
    init(onFinish: @escaping () -> Void, initialStep: Step = .welcome) {
        self.onFinish = onFinish
        _step = StateVar(initialValue: initialStep)
    }
    @Environment(AppModel.self) private var model
    @Environment(\.openURL) private var openURL
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @StateVar private var step: Step = .welcome
    @StateVar private var scanStarted = false
    @StateVar private var drawn = false
    @StateVar private var showInstall = false

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                if step != .welcome {
                    Text("Step \(step.rawValue) of \(Step.allCases.count - 1)").font(.callout).foregroundStyle(.secondary)
                }
                Spacer()
                if step != .firstScan {
                    Button("Skip for now") { advance() }.buttonStyle(.link)
                }
            }
            .padding(.horizontal, Spacing.xl).padding(.top, Spacing.l)
            .frame(height: 40)

            Group {
                switch step {
                case .welcome: welcome
                case .permissions: permissions
                case .firstScan: firstScan
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .padding(.horizontal, 48)
            .transition(.opacity)

            HStack(spacing: 8) {
                ForEach(Step.allCases, id: \.rawValue) { s in
                    Circle().fill(s == step ? Color.rampartTeal : Color.secondary.opacity(0.3)).frame(width: 7, height: 7)
                }
            }
            .padding(.bottom, Spacing.l)
            .accessibilityElement(children: .ignore)
            .accessibilityLabel("Step \(step.rawValue + 1) of \(Step.allCases.count)")
        }
        .frame(width: 680, height: 600)
        .background(AppBackdrop())
        .sheet(isPresented: $showInstall) { InstallFullProtectionSheet() }
        .onReceive(NotificationCenter.default.publisher(for: .rampartOnboardingAdvance)) { _ in advance() }
    }

    private func advance() {
        withAnimation(reduceMotion ? nil : .easeInOut(duration: 0.25)) {
            if let next = Step(rawValue: step.rawValue + 1) { step = next } else { onFinish() }
        }
    }

    private func page<Content: View>(symbol: String, tint: Color = .rampartTeal, title: String, body: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(spacing: Spacing.l) {
            Spacer()
            if symbol == "brand" {
                RamPartMark(size: 112)
            } else {
                ShieldHero(symbol: symbol, tint: tint, breathe: false, size: 112)
            }
            Text(title).font(.largeTitle.weight(.bold)).fontDesign(.rounded).multilineTextAlignment(.center)
            Text(body).font(.title3).foregroundStyle(.secondary).multilineTextAlignment(.center).fixedSize(horizontal: false, vertical: true)
            content()
            Spacer()
        }
    }

    private var permissions: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            PermissionsChecklistView()
            HStack {
                Spacer()
                Button("Continue") { advance() }.buttonStyle(GlowButtonStyle()).controlSize(.large).keyboardShortcut(.defaultAction)
            }
        }
        .padding(.top, Spacing.s)
    }

    private var welcome: some View {
        page(symbol: "brand", title: "Welcome to \(Product.name)",
             body: "\(Product.name) protects your Mac quietly in the background. We'll set up permissions in one place, then run a quick check. It takes about 2 minutes.") {
            Button("Get Started") { advance() }.buttonStyle(GlowButtonStyle()).controlSize(.large).keyboardShortcut(.defaultAction)
                .padding(.top, Spacing.s)
            Text("No ads. No upsells. Your files stay on your Mac.").font(.callout).foregroundStyle(.secondary)
        }
    }

    @ViewBuilder private var firstScan: some View {
        let p = model.scanProgress
        if case .finished(let rec, let found) = model.scanPhase, scanStarted {
            page(symbol: found.isEmpty ? "checkmark.shield.fill" : "archivebox.fill", tint: found.isEmpty ? .statusProtected : .gray,
                 title: found.isEmpty ? "All set. Your Mac is protected." : "Found \(found.count) item\(found.count == 1 ? "" : "s"). \(found.count == 1 ? "It's" : "They're") in quarantine and can't run.",
                 body: "Checked \(Fmt.count(rec.scanned)) files in \(Fmt.duration(rec.seconds)). Security Score: \(model.securityScore) · \(AppModel.scoreLabel(model.securityScore)).") {
                if !found.isEmpty {
                    VStack(spacing: 0) { ForEach(found.prefix(3)) { DetectionRowSummary(detection: $0).padding(Spacing.s) } }
                        .card(padding: Spacing.s).frame(maxWidth: 460)
                }
                if model.mode == .live && model.source == .basic {
                    VStack(spacing: Spacing.s) {
                        Text("Basic protection is running. For web protection and system-wide monitoring, enable full protection. macOS will ask for your password once.")
                            .font(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center).frame(maxWidth: 460)
                        Button("Enable Full Protection…") { showInstall = true }
                    }
                }
                Button(found.isEmpty ? "Open \(Product.name)" : "Review") {
                    model.scanPhase = .idle
                    if !found.isEmpty { model.selection = .threats }
                    onFinish()
                }
                .buttonStyle(GlowButtonStyle()).controlSize(.large).keyboardShortcut(.defaultAction)
            }
        } else if model.mode == .connecting {
            page(symbol: "brand", title: "Starting protection…",
                 body: "\(Product.name) is starting its background checker. This only takes a moment and doesn't install anything.") {
                ProgressView().controlSize(.regular)
            }
            .onChange(of: model.mode) { _, m in if m != .connecting { beginFirstScan() } }
        } else if model.mode == .offline {
            page(symbol: "shield.slash", tint: .statusAction, title: "Protection service isn't running",
                 body: model.lastError ?? "\(Product.name) couldn't start its background checker, so it can't run a first scan yet.") {
                HStack {
                    Button("Retry") { Task { await model.retry(); beginFirstScan() } }.buttonStyle(GlowButtonStyle()).controlSize(.large)
                    Button("Finish Without Scanning") { onFinish() }
                }
            }
        } else {
            page(symbol: "magnifyingglass", title: "Let's do a quick check",
                 body: "This takes about a minute. You can close this window — the scan continues.") {
                ProgressView(value: p?.fraction ?? 0).tint(Color.rampartTeal).frame(maxWidth: 360)
                Text(p.map { $0.total > 0 ? "\(Fmt.count($0.scanned)) of \(Fmt.count($0.total)) files" : "Estimating files…" } ?? "Starting…")
                    .font(.callout).foregroundStyle(.secondary).monospacedDigit()
                if let cur = p?.current, !cur.isEmpty {
                    Text(cur.replacingOccurrences(of: NSHomeDirectory(), with: "~"))
                        .font(.caption.monospaced()).foregroundStyle(.tertiary).lineLimit(1).truncationMode(.middle).frame(maxWidth: 420)
                }
                if let n = p?.found, n > 0 { Text("\(n) item\(n == 1 ? "" : "s") found so far").font(.callout) }
                Button("Continue in Background") { onFinish() }.buttonStyle(.link)
            }
            .onAppear { beginFirstScan() }
        }
    }

    private func beginFirstScan() {
        guard !scanStarted, model.mode != .connecting, !Headless.active else { return }
        scanStarted = true
        if model.isScanning { return }
        model.scanPhase = .idle
        model.startScan(.quick)
    }
}
