import Foundation
import RampartWeb
import RampartAI

/// Bridges RampartAI's Gemini scam opinion into RampartWeb's ScamAIAssessor protocol.
extension GeminiScamAssessor: ScamAIAssessor {
    public func assess(input: String, kind: ScamInputKind, offlineReport: ScamReport) async throws -> ScamAIOpinion {
        let a = try await assess(input: input, kindRaw: kind.rawValue, localSignals: offlineReport.signals.map { $0.title })
        return ScamAIOpinion(verdict: ScamVerdict(rawValue: a.webVerdictRaw) ?? .suspicious, confidence: a.confidence,
                             summary: a.summary, reasons: a.reasons, provider: "Gemini")
    }
}

enum ScamAIWiring {
    @MainActor static func install() {
        ScamCheckModel.aiAssessor = GeminiScamAssessor(service: AIChatModel.shared.service)
    }
}
