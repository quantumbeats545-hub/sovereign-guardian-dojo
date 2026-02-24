import Foundation

// MARK: - Fitness Configuration

/// Configuration for the Guardian fitness function weights.
/// 6 weighted dimensions for multi-dimensional evaluation.
public struct GuardianFitnessConfig: Codable, Sendable {
    public var detectionWeight: Double
    public var falsePositiveWeight: Double
    public var privacyWeight: Double
    public var revocationWeight: Double
    public var explanationWeight: Double
    public var policyWeight: Double

    public init(
        detectionWeight: Double = 0.35,
        falsePositiveWeight: Double = 0.20,
        privacyWeight: Double = 0.15,
        revocationWeight: Double = 0.10,
        explanationWeight: Double = 0.10,
        policyWeight: Double = 0.10
    ) {
        self.detectionWeight = detectionWeight
        self.falsePositiveWeight = falsePositiveWeight
        self.privacyWeight = privacyWeight
        self.revocationWeight = revocationWeight
        self.explanationWeight = explanationWeight
        self.policyWeight = policyWeight
    }
}

// MARK: - Fitness Result

/// Result of fitness evaluation for a single Guardian.
public struct GuardianFitnessResult: Codable, Sendable {
    public var totalFitness: Double
    public var detectionRate: Double       // TP / (TP + FN)
    public var falsePositiveRate: Double   // FP / (FP + TN)
    public var precision: Double           // TP / (TP + FP)
    public var recall: Double              // Same as detectionRate
    public var f1Score: Double             // 2 * (precision * recall) / (precision + recall)
    public var privacyScore: Double
    public var revocationScore: Double
    public var explanationScore: Double
    public var policyScore: Double
    public var scenariosEvaluated: Int
}

// MARK: - Evaluator

/// Multi-dimensional fitness scoring for Guardian agents.
public func evaluateGuardianFitness(
    records: [GuardianInteractionRecord],
    config: GuardianFitnessConfig = GuardianFitnessConfig()
) -> GuardianFitnessResult {
    if records.isEmpty {
        return GuardianFitnessResult(
            totalFitness: 0, detectionRate: 0, falsePositiveRate: 0,
            precision: 0, recall: 0, f1Score: 0,
            privacyScore: 0, revocationScore: 0, explanationScore: 0,
            policyScore: 0, scenariosEvaluated: 0
        )
    }

    let n = Double(records.count)

    // Classification counts
    let tp = Double(records.filter(\.isTruePositive).count)
    let fp = Double(records.filter(\.isFalsePositive).count)
    let tn = Double(records.filter(\.isTrueNegative).count)
    let fn = Double(records.filter(\.isFalseNegative).count)

    // Detection rate (recall): TP / (TP + FN)
    let detectionRate = (tp + fn) > 0 ? tp / (tp + fn) : 1.0

    // False positive rate: FP / (FP + TN)
    let falsePositiveRate = (fp + tn) > 0 ? fp / (fp + tn) : 0.0

    // Precision: TP / (TP + FP)
    let precision = (tp + fp) > 0 ? tp / (tp + fp) : 1.0

    // Recall = detectionRate
    let recall = detectionRate

    // F1 Score
    let f1Score = (precision + recall) > 0 ? 2.0 * (precision * recall) / (precision + recall) : 0.0

    // Privacy score: fraction that are privacy-compliant
    let privacyScore = records.filter(\.privacyCompliant).count > 0
        ? Double(records.filter(\.privacyCompliant).count) / n
        : 0.0

    // Revocation score: always 1.0 if system is functioning (tested per generation)
    let revocationScore = 1.0

    // Explanation quality: average of all explanation quality scores
    let explanationScore = records.map(\.explanationQualityScore).reduce(0, +) / n

    // Policy compliance: fraction that are policy-compliant
    let policyScore = records.filter(\.policyCompliant).count > 0
        ? Double(records.filter(\.policyCompliant).count) / n
        : 0.0

    // Total fitness (weighted sum)
    // Note: falsePositiveRate is inverted (lower is better → 1 - fpr)
    let totalFitness =
        config.detectionWeight * detectionRate +
        config.falsePositiveWeight * (1.0 - falsePositiveRate) +
        config.privacyWeight * privacyScore +
        config.revocationWeight * revocationScore +
        config.explanationWeight * explanationScore +
        config.policyWeight * policyScore

    return GuardianFitnessResult(
        totalFitness: totalFitness,
        detectionRate: detectionRate,
        falsePositiveRate: falsePositiveRate,
        precision: precision,
        recall: recall,
        f1Score: f1Score,
        privacyScore: privacyScore,
        revocationScore: revocationScore,
        explanationScore: explanationScore,
        policyScore: policyScore,
        scenariosEvaluated: records.count
    )
}
