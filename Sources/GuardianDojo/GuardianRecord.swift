import Foundation
import CryptoKit

/// A record of a Guardian's evaluation of a single scenario.
/// Mirrors the `InteractionRecord` pattern from DojoCore but for family protection.
public struct GuardianInteractionRecord: Codable, Sendable, Identifiable {
    public var id: String
    public var sessionId: String
    public var guardianId: String
    public var generation: UInt32
    public var round: UInt32

    // Scenario details
    public var scenarioId: String
    public var scenarioType: GuardianScenarioType
    public var profileType: GuardianProfileType
    public var platform: String
    public var difficulty: ScenarioDifficulty

    // Guardian's response
    public var decision: GuardianDecision
    public var confidence: Double
    public var explanation: String

    // Evaluation against ground truth
    public var isTruePositive: Bool
    public var isFalsePositive: Bool
    public var isTrueNegative: Bool
    public var isFalseNegative: Bool

    // Quality scores
    public var explanationQualityScore: Double
    public var privacyCompliant: Bool
    public var policyCompliant: Bool

    // Audit
    public var evidenceHash: String
    public var timestamp: Date

    public init(
        sessionId: String,
        guardianId: String,
        generation: UInt32,
        round: UInt32,
        scenarioId: String,
        scenarioType: GuardianScenarioType,
        profileType: GuardianProfileType,
        platform: String,
        difficulty: ScenarioDifficulty,
        decision: GuardianDecision,
        confidence: Double,
        explanation: String,
        isTruePositive: Bool = false,
        isFalsePositive: Bool = false,
        isTrueNegative: Bool = false,
        isFalseNegative: Bool = false,
        explanationQualityScore: Double = 0.0,
        privacyCompliant: Bool = true,
        policyCompliant: Bool = true
    ) {
        self.id = "\(sessionId)-\(guardianId)-\(scenarioId)"
        self.sessionId = sessionId
        self.guardianId = guardianId
        self.generation = generation
        self.round = round
        self.scenarioId = scenarioId
        self.scenarioType = scenarioType
        self.profileType = profileType
        self.platform = platform
        self.difficulty = difficulty
        self.decision = decision
        self.confidence = confidence
        self.explanation = explanation
        self.isTruePositive = isTruePositive
        self.isFalsePositive = isFalsePositive
        self.isTrueNegative = isTrueNegative
        self.isFalseNegative = isFalseNegative
        self.explanationQualityScore = explanationQualityScore
        self.privacyCompliant = privacyCompliant
        self.policyCompliant = policyCompliant
        self.timestamp = Date()

        // Evidence hash for audit trail
        let evidenceString = "\(sessionId)\(guardianId)\(scenarioId)\(decision.rawValue)\(confidence)"
        let digest = SHA256.hash(data: Data(evidenceString.utf8))
        self.evidenceHash = digest.map { String(format: "%02x", $0) }.joined()
    }

    /// Compute classification result from ground truth.
    public static func classify(
        decision: GuardianDecision,
        groundTruth: GroundTruth
    ) -> (tp: Bool, fp: Bool, tn: Bool, fn: Bool) {
        let guardianBlockedOrEscalated = decision == .block || decision == .escalate || decision == .alert
        let isThreat = groundTruth.isThreat

        let tp = isThreat && guardianBlockedOrEscalated
        let fp = !isThreat && guardianBlockedOrEscalated
        let tn = !isThreat && !guardianBlockedOrEscalated
        let fn = isThreat && !guardianBlockedOrEscalated

        return (tp: tp, fp: fp, tn: tn, fn: fn)
    }
}
