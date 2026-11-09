import Foundation
import AVFoundation
import Speech
import Observation
import RampartShared

/// Push-to-talk for the floating bot: Apple's Speech framework (on-device when the Mac supports it) and
/// AVSpeechSynthesizer for short spoken replies (behind the mute toggle).
/// Microphone and speech permission are asked only when the user first presses the voice button, never at launch.
@MainActor
@Observable
final class BotVoice {
    static let shared = BotVoice()

    private(set) var listening = false
    private(set) var transcript = ""
    /// A calm one-liner when voice can't run (permission denied, no recogniser, missing usage text).
    private(set) var notice: String?

    @ObservationIgnored private var engine: AVAudioEngine?
    @ObservationIgnored private var request: SFSpeechAudioBufferRecognitionRequest?
    @ObservationIgnored private var task: SFSpeechRecognitionTask?
    @ObservationIgnored private var cap: DispatchWorkItem?
    @ObservationIgnored private let synth = AVSpeechSynthesizer()

    static let maxSeconds: TimeInterval = 30

    func toggle() { if listening { stop(send: true) } else { Task { await start() } } }

    func start() async {
        notice = nil
        // Without the usage strings macOS would terminate the app on the permission request, so check first.
        let info = Bundle.main.infoDictionary ?? [:]
        guard info["NSMicrophoneUsageDescription"] != nil, info["NSSpeechRecognitionUsageDescription"] != nil else {
            notice = "Voice input isn't available in this build of \(Product.name) yet. You can still type."
            return
        }
        let speechOK: Bool = await withCheckedContinuation { c in
            SFSpeechRecognizer.requestAuthorization { c.resume(returning: $0 == .authorized) }
        }
        guard speechOK else { notice = Self.deniedText; return }
        let micOK: Bool
        switch AVCaptureDevice.authorizationStatus(for: .audio) {
        case .authorized: micOK = true
        case .notDetermined: micOK = await AVCaptureDevice.requestAccess(for: .audio)
        default: micOK = false
        }
        guard micOK else { notice = Self.deniedText; return }
        guard let recognizer = SFSpeechRecognizer(locale: Locale.current) ?? SFSpeechRecognizer(locale: Locale(identifier: "en-US")),
              recognizer.isAvailable else {
            notice = "Speech recognition isn't available right now. You can still type."
            return
        }
        let req = SFSpeechAudioBufferRecognitionRequest()
        req.shouldReportPartialResults = true
        if recognizer.supportsOnDeviceRecognition { req.requiresOnDeviceRecognition = true }
        let engine = AVAudioEngine()
        let input = engine.inputNode
        let format = input.outputFormat(forBus: 0)
        guard format.channelCount > 0 else { notice = "No microphone found. You can still type."; return }
        input.installTap(onBus: 0, bufferSize: 1024, format: format) { buffer, _ in req.append(buffer) }
        do { engine.prepare(); try engine.start() } catch {
            input.removeTap(onBus: 0)
            notice = "Couldn't start the microphone. You can still type."
            return
        }
        self.engine = engine; self.request = req
        transcript = ""
        listening = true
        stopSpeaking()
        BotController.shared.send(.voiceListening)
        task = recognizer.recognitionTask(with: req) { result, error in
            let text = result?.bestTranscription.formattedString
            let final = result?.isFinal ?? false
            Task { @MainActor in
                let v = BotVoice.shared
                guard v.listening else { return }
                if let text { v.transcript = text }
                if final || error != nil { v.stop(send: final) }
            }
        }
        let w = DispatchWorkItem { [weak self] in self?.stop(send: true) }
        cap = w
        DispatchQueue.main.asyncAfter(deadline: .now() + Self.maxSeconds, execute: w)
    }

    /// Ends listening; with `send`, the transcript goes to the assistant (spoken reply unless muted).
    func stop(send: Bool) {
        guard listening else { return }
        listening = false
        cap?.cancel(); cap = nil
        engine?.inputNode.removeTap(onBus: 0)
        engine?.stop(); engine = nil
        request?.endAudio(); request = nil
        task?.cancel(); task = nil
        BotController.shared.send(.voiceStopped)
        let text = transcript.trimmingCharacters(in: .whitespacesAndNewlines)
        transcript = ""
        guard send, !text.isEmpty else { return }
        let chat = AIChatModel.shared
        guard chat.enabled, chat.keyStatus == .present, !chat.isSending else {
            notice = "Turn on the assistant first, then try again."
            return
        }
        chat.draft = String(text.prefix(2000))
        BotController.shared.replyBySpeech = true
        chat.send(posture: AppModel.shared.posture)
    }

    /// Speaks a short version of a reply: the first sentence or two, sanitised (no paths, keys or addresses).
    func speak(_ text: String) {
        let short = Self.spokenSummary(text)
        guard !short.isEmpty, !BotController.shared.voiceMuted else { return }
        synth.stopSpeaking(at: .immediate)
        synth.speak(AVSpeechUtterance(string: short))
    }

    func stopSpeaking() { if synth.isSpeaking { synth.stopSpeaking(at: .immediate) } }

    nonisolated static func spokenSummary(_ text: String) -> String {
        let clean = BotBubble.sanitize(text, max: 400)
        var out = ""
        for s in clean.split(separator: ".", omittingEmptySubsequences: true) {
            let next = out + s.trimmingCharacters(in: .whitespaces) + ". "
            if next.count > 200 && !out.isEmpty { break }
            out = next
            if out.count > 120 { break }
        }
        return String(out.trimmingCharacters(in: .whitespaces).prefix(220))
    }

    static let deniedText = "Voice is off because Microphone or Speech Recognition access isn't allowed. You can allow both for \(Product.name) in System Settings › Privacy & Security, or just type."
}
