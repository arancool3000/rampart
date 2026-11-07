import RampartShared
import AppKit
import SwiftUI
import UniformTypeIdentifiers

/// Copies the running bundle into /Applications (temporary name, then swap). Never deletes the running copy.
@MainActor
@Observable
final class ApplicationsMover {
    static let shared = ApplicationsMover()

    enum Phase: Equatable { case idle, confirmReplace, copying, done, failed(String) }
    private(set) var phase: Phase = .idle

    var source: URL { Bundle.main.bundleURL }
    var destination: URL { URL(fileURLWithPath: "/Applications").appendingPathComponent(source.lastPathComponent) }
    static var runsFromApplications: Bool { Bundle.main.bundlePath.hasPrefix("/Applications/") }

    func requestMove() {
        guard phase != .copying else { return }
        if FileManager.default.fileExists(atPath: destination.path) { phase = .confirmReplace } else { copy(replacing: false) }
    }

    func cancelReplace() { phase = .idle }

    func copy(replacing: Bool) {
        let src = source, dst = destination
        guard src.standardizedFileURL.path != dst.standardizedFileURL.path else { phase = .failed("This copy is already in Applications."); return }
        phase = .copying
        Task.detached(priority: .userInitiated) {
            let fm = FileManager.default
            let tmp = dst.deletingLastPathComponent().appendingPathComponent(".\(dst.lastPathComponent).\(UUID().uuidString).tmp")
            do {
                try fm.copyItem(at: src, to: tmp)
                if replacing, fm.fileExists(atPath: dst.path) {
                    _ = try fm.replaceItemAt(dst, withItemAt: tmp, backupItemName: nil, options: [])
                } else {
                    try fm.moveItem(at: tmp, to: dst)
                }
                await MainActor.run { ApplicationsMover.shared.phase = .done }
            } catch {
                try? fm.removeItem(at: tmp)
                let msg = (error as NSError).code == NSFileWriteNoPermissionError
                    ? "macOS didn't allow writing to Applications. Drag \(Product.name) there in Finder instead."
                    : error.localizedDescription
                await MainActor.run { ApplicationsMover.shared.phase = .failed(msg) }
            }
        }
    }

    func relaunchFromApplications() {
        let cfg = NSWorkspace.OpenConfiguration()
        cfg.createsNewApplicationInstance = true
        NSWorkspace.shared.openApplication(at: destination, configuration: cfg) { app, error in
            Task { @MainActor in
                if let error { ApplicationsMover.shared.phase = .failed(error.localizedDescription) }
                else if app != nil { NSApp.terminate(nil) }
            }
        }
    }
}

/// Small window controller for the drag-to-Applications sheet.
@MainActor
enum InstallToApplicationsWindow {
    private static var window: NSWindow?

    /// Shows the window unless the app already runs from /Applications (or in a headless run).
    static func showIfNeeded() {
        guard !ApplicationsMover.runsFromApplications, !Headless.active else { return }
        if let w = window { w.makeKeyAndOrderFront(nil); return }
        let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 520, height: 360),
                         styleMask: [.titled, .closable, .fullSizeContentView], backing: .buffered, defer: false)
        w.titlebarAppearsTransparent = true
        w.titleVisibility = .hidden
        w.isMovableByWindowBackground = true
        w.isReleasedWhenClosed = false
        w.title = "Move \(Product.name) to Applications"
        w.contentView = NSHostingView(rootView: InstallToApplicationsView())
        w.center()
        window = w
        NotificationCenter.default.addObserver(forName: NSWindow.willCloseNotification, object: w, queue: .main) { _ in
            Task { @MainActor in window = nil }
        }
        w.makeKeyAndOrderFront(nil)
    }
}

struct InstallToApplicationsView: View {
    private let mover = ApplicationsMover.shared
    @StateVar private var targeted = false
    @StateVar private var arrowPhase = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    private var appIcon: NSImage { NSWorkspace.shared.icon(forFile: Bundle.main.bundlePath) }
    private var folderIcon: NSImage { NSWorkspace.shared.icon(forFile: "/Applications") }
    private var busy: Bool { mover.phase == .copying }

    var body: some View {
        VStack(spacing: 18) {
            VStack(spacing: 6) {
                Text("Move \(Product.name) to Applications").font(.title2.weight(.semibold))
                Text("Full protection runs from your Applications folder. Drag the icon across, or let \(Product.name) do it.")
                    .font(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack(spacing: 28) {
                Image(nsImage: appIcon).resizable().frame(width: 96, height: 96)
                    .draggable(mover.source) { Image(nsImage: appIcon).resizable().frame(width: 72, height: 72) }
                    .accessibilityLabel("\(Product.name) app icon. Drag to the Applications folder.")
                    .help("Drag onto Applications")
                arrow
                Image(nsImage: folderIcon).resizable().frame(width: 96, height: 96)
                    .scaleEffect(targeted ? 1.08 : 1)
                    .background(RoundedRectangle(cornerRadius: 18).fill(Color.accentColor.opacity(targeted ? 0.18 : 0)).padding(-8))
                    .animation(reduceMotion ? nil : .spring(response: 0.3, dampingFraction: 0.7), value: targeted)
                    .dropDestination(for: URL.self) { urls, _ in
                        guard urls.contains(where: { $0.standardizedFileURL == mover.source.standardizedFileURL }) else { return false }
                        mover.requestMove(); return true
                    } isTargeted: { targeted = $0 }
                    .accessibilityLabel("Applications folder")
            }
            .padding(.vertical, 8)
            status.frame(minHeight: 44)
            buttons
        }
        .padding(28)
        .frame(width: 520)
        .onAppear { arrowPhase = true }
        .onDisappear { arrowPhase = false }
    }

    private var arrow: some View {
        Image(systemName: "arrow.right")
            .font(.system(size: 28, weight: .semibold))
            .foregroundStyle(Color.accentColor)
            .offset(x: (arrowPhase && !reduceMotion && mover.phase == .idle) ? 8 : -4)
            .opacity(arrowPhase ? 1 : 0.5)
            // Finite: a few gentle nudges, then rest (keeps idle CPU at zero).
            .animation(reduceMotion ? nil : .easeInOut(duration: 0.7).repeatCount(7, autoreverses: true), value: arrowPhase)
            .accessibilityHidden(true)
    }

    @ViewBuilder private var status: some View {
        switch mover.phase {
        case .idle:
            Text("Your current copy stays where it is until you relaunch.").font(.caption).foregroundStyle(.secondary)
        case .confirmReplace:
            Text("A copy of \(Product.name) is already in Applications. Replace it with this one?")
                .font(.callout).multilineTextAlignment(.center)
        case .copying:
            HStack(spacing: 8) { ProgressView().controlSize(.small); Text("Copying to Applications…").font(.callout) }
        case .done:
            Label("Copied. Relaunch from Applications to continue.", systemImage: "checkmark.circle.fill")
                .font(.callout).foregroundStyle(.green)
        case .failed(let msg):
            Label(msg, systemImage: "exclamationmark.triangle.fill").font(.callout).foregroundStyle(.orange)
                .multilineTextAlignment(.center)
        }
    }

    @ViewBuilder private var buttons: some View {
        HStack {
            switch mover.phase {
            case .confirmReplace:
                Button("Keep Existing") { mover.cancelReplace() }.keyboardShortcut(.cancelAction)
                Button("Replace") { mover.copy(replacing: true) }.keyboardShortcut(.defaultAction)
            case .done:
                Button("Relaunch from Applications") { mover.relaunchFromApplications() }.keyboardShortcut(.defaultAction)
            default:
                Button("Move for Me") { mover.requestMove() }.keyboardShortcut(.defaultAction).disabled(busy)
            }
        }
        .controlSize(.large)
    }
}
