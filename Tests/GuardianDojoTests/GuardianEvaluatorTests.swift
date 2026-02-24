import XCTest
@testable import GuardianDojo

final class GuardianEvaluatorTests: XCTestCase {

    // MARK: - Helper

    private func makeRecord(
        decision: GuardianDecision,
        groundTruth: GroundTruth,
        explanationQuality: Double = 0.7,
        privacyCompliant: Bool = true,
        policyCompliant: Bool = true
    ) -> GuardianInteractionRecord {
        let classification = GuardianInteractionRecord.classify(decision: decision, groundTruth: groundTruth)
        return GuardianInteractionRecord(
            sessionId: UUID().uuidString,
            guardianId: "test-guardian",
            generation: 0,
            round: 0,
            scenarioId: UUID().uuidString,
            scenarioType: groundTruth.threatCategory ?? .grooming,
            profileType: .child,
            platform: "Discord",
            difficulty: .medium,
            decision: decision,
            confidence: 0.9,
            explanation: "Test explanation",
            isTruePositive: classification.tp,
            isFalsePositive: classification.fp,
            isTrueNegative: classification.tn,
            isFalseNegative: classification.fn,
            explanationQualityScore: explanationQuality,
            privacyCompliant: privacyCompliant,
            policyCompliant: policyCompliant
        )
    }

    // MARK: - Perfect Guardian

    func testPerfectGuardianScoresHigh() {
        // Guardian correctly blocks all threats and allows all safe content
        var records: [GuardianInteractionRecord] = []

        let threatGT = GroundTruth(isThreat: true, correctDecision: .block, threatCategory: .grooming, severity: 0.9)
        let safeGT = GroundTruth(isThreat: false, correctDecision: .allow)

        for _ in 0..<70 {
            records.append(makeRecord(decision: .block, groundTruth: threatGT))
        }
        for _ in 0..<30 {
            records.append(makeRecord(decision: .allow, groundTruth: safeGT))
        }

        let result = evaluateGuardianFitness(records: records)

        XCTAssertEqual(result.detectionRate, 1.0)
        XCTAssertEqual(result.falsePositiveRate, 0.0)
        XCTAssertEqual(result.precision, 1.0)
        XCTAssertEqual(result.f1Score, 1.0)
        XCTAssertGreaterThan(result.totalFitness, 0.9, "Perfect guardian should score > 0.9")
    }

    // MARK: - Terrible Guardian

    func testTerribleGuardianScoresLow() {
        // Guardian allows all threats and blocks all safe content
        var records: [GuardianInteractionRecord] = []

        let threatGT = GroundTruth(isThreat: true, correctDecision: .block, threatCategory: .grooming, severity: 0.9)
        let safeGT = GroundTruth(isThreat: false, correctDecision: .allow)

        for _ in 0..<70 {
            records.append(makeRecord(decision: .allow, groundTruth: threatGT))
        }
        for _ in 0..<30 {
            records.append(makeRecord(decision: .block, groundTruth: safeGT))
        }

        let result = evaluateGuardianFitness(records: records)

        XCTAssertEqual(result.detectionRate, 0.0, "Terrible guardian detects nothing")
        XCTAssertEqual(result.falsePositiveRate, 1.0, "Terrible guardian blocks only safe content")
        XCTAssertLessThan(result.totalFitness, 0.5, "Terrible guardian should score < 0.5")
    }

    // MARK: - Correct Scores Higher Than Incorrect

    func testCorrectDecisionsScoreHigherThanIncorrect() {
        let threatGT = GroundTruth(isThreat: true, correctDecision: .block, threatCategory: .phishing, severity: 0.8)
        let safeGT = GroundTruth(isThreat: false, correctDecision: .allow)

        // Correct guardian
        var correctRecords: [GuardianInteractionRecord] = []
        for _ in 0..<50 {
            correctRecords.append(makeRecord(decision: .block, groundTruth: threatGT))
        }
        for _ in 0..<50 {
            correctRecords.append(makeRecord(decision: .allow, groundTruth: safeGT))
        }

        // Incorrect guardian
        var incorrectRecords: [GuardianInteractionRecord] = []
        for _ in 0..<50 {
            incorrectRecords.append(makeRecord(decision: .allow, groundTruth: threatGT))
        }
        for _ in 0..<50 {
            incorrectRecords.append(makeRecord(decision: .block, groundTruth: safeGT))
        }

        let correctFitness = evaluateGuardianFitness(records: correctRecords)
        let incorrectFitness = evaluateGuardianFitness(records: incorrectRecords)

        XCTAssertGreaterThan(correctFitness.totalFitness, incorrectFitness.totalFitness)
    }

    // MARK: - Empty Records

    func testEmptyRecordsReturnZero() {
        let result = evaluateGuardianFitness(records: [])
        XCTAssertEqual(result.totalFitness, 0.0)
        XCTAssertEqual(result.scenariosEvaluated, 0)
    }

    // MARK: - Fitness Weights

    func testCustomWeights() {
        let threatGT = GroundTruth(isThreat: true, correctDecision: .block, threatCategory: .grooming, severity: 0.9)
        var records: [GuardianInteractionRecord] = []
        for _ in 0..<100 {
            records.append(makeRecord(decision: .block, groundTruth: threatGT))
        }

        // Detection-only config
        let detectionOnly = GuardianFitnessConfig(
            detectionWeight: 1.0,
            falsePositiveWeight: 0.0,
            privacyWeight: 0.0,
            revocationWeight: 0.0,
            explanationWeight: 0.0,
            policyWeight: 0.0
        )

        let result = evaluateGuardianFitness(records: records, config: detectionOnly)
        XCTAssertEqual(result.totalFitness, result.detectionRate, accuracy: 0.001)
    }

    // MARK: - F1 Score

    func testF1ScoreCalculation() {
        let threatGT = GroundTruth(isThreat: true, correctDecision: .block, threatCategory: .grooming, severity: 0.9)
        let safeGT = GroundTruth(isThreat: false, correctDecision: .allow)

        // 80% recall, some false positives
        var records: [GuardianInteractionRecord] = []
        for _ in 0..<80 { records.append(makeRecord(decision: .block, groundTruth: threatGT)) }  // TP
        for _ in 0..<20 { records.append(makeRecord(decision: .allow, groundTruth: threatGT)) }  // FN
        for _ in 0..<10 { records.append(makeRecord(decision: .block, groundTruth: safeGT)) }   // FP
        for _ in 0..<40 { records.append(makeRecord(decision: .allow, groundTruth: safeGT)) }   // TN

        let result = evaluateGuardianFitness(records: records)

        // TP=80, FP=10, TN=40, FN=20
        XCTAssertEqual(result.detectionRate, 0.8, accuracy: 0.01)  // 80/100
        XCTAssertEqual(result.falsePositiveRate, 0.2, accuracy: 0.01)  // 10/50
        XCTAssertEqual(result.precision, 80.0/90.0, accuracy: 0.01)  // 80/90
        XCTAssertGreaterThan(result.f1Score, 0.0)
        XCTAssertLessThan(result.f1Score, 1.0)
    }

    // MARK: - Privacy & Policy Scores

    func testPrivacyNonComplianceLowersFitness() {
        let threatGT = GroundTruth(isThreat: true, correctDecision: .block, threatCategory: .grooming, severity: 0.9)

        let compliantRecords = (0..<50).map { _ in
            makeRecord(decision: .block, groundTruth: threatGT, privacyCompliant: true)
        }
        let nonCompliantRecords = (0..<50).map { _ in
            makeRecord(decision: .block, groundTruth: threatGT, privacyCompliant: false)
        }

        let compliantFitness = evaluateGuardianFitness(records: compliantRecords)
        let nonCompliantFitness = evaluateGuardianFitness(records: nonCompliantRecords)

        XCTAssertGreaterThan(compliantFitness.totalFitness, nonCompliantFitness.totalFitness)
    }
}
