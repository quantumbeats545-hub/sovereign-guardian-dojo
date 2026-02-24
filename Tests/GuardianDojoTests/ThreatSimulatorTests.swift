import XCTest
@testable import GuardianDojo

final class ThreatSimulatorTests: XCTestCase {
    let simulator = ThreatSimulator()

    // MARK: - Scenario Generation

    func testGenerateScenarioForAllTypes() {
        for type in GuardianScenarioType.allCases {
            let scenario = simulator.generateScenario(type: type)
            XCTAssertEqual(scenario.context.scenarioType, type)
            XCTAssertFalse(scenario.context.threatContent.isEmpty, "Content empty for \(type)")
            XCTAssertTrue(scenario.context.groundTruth.isThreat, "Ground truth should be threat for \(type)")
        }
    }

    func testGenerateScenarioForAllDifficulties() {
        for difficulty in ScenarioDifficulty.allCases {
            let scenario = simulator.generateScenario(type: .grooming, difficulty: difficulty)
            XCTAssertEqual(scenario.difficulty, difficulty)
            XCTAssertFalse(scenario.context.threatContent.isEmpty)
        }
    }

    func testGenerateScenarioForAllProfiles() {
        for profile in GuardianProfileType.allCases {
            let scenario = simulator.generateScenario(type: .phishing, profileType: profile)
            XCTAssertEqual(scenario.context.profileType, profile)
        }
    }

    func testGenerateBenignScenario() {
        let scenario = simulator.generateBenignScenario()
        XCTAssertFalse(scenario.context.groundTruth.isThreat)
        XCTAssertEqual(scenario.context.groundTruth.correctDecision, .allow)
        XCTAssertFalse(scenario.context.threatContent.isEmpty)
    }

    func testGenerateBenignScenarioForSenior() {
        let scenario = simulator.generateBenignScenario(profileType: .senior)
        XCTAssertEqual(scenario.context.profileType, .senior)
        XCTAssertFalse(scenario.context.groundTruth.isThreat)
    }

    // MARK: - Batch Generation

    func testGenerateBatchCount() {
        let batch = simulator.generateBatch(count: 50)
        XCTAssertEqual(batch.count, 50)
    }

    func testGenerateBatchDistribution() {
        let count = 100
        let distribution = 0.7
        let batch = simulator.generateBatch(count: count, distribution: distribution)

        let threats = batch.filter { $0.context.groundTruth.isThreat }.count
        let safe = batch.filter { !$0.context.groundTruth.isThreat }.count

        XCTAssertEqual(threats, 70)
        XCTAssertEqual(safe, 30)
        XCTAssertEqual(threats + safe, count)
    }

    func testGenerateBatchOver100Scenarios() {
        let batch = simulator.generateBatch(count: 120, profileType: .child)
        XCTAssertEqual(batch.count, 120)

        // Verify all have valid IDs and content
        for scenario in batch {
            XCTAssertFalse(scenario.id.isEmpty)
            XCTAssertFalse(scenario.context.threatContent.isEmpty)
        }
    }

    // MARK: - Ground Truth Accuracy

    func testGroomingScenarioHasCorrectSeverity() {
        let scenario = simulator.generateScenario(type: .grooming)
        XCTAssertEqual(scenario.context.groundTruth.severity, 0.95)
        XCTAssertEqual(scenario.context.groundTruth.correctDecision, .escalate)
    }

    func testSelfHarmScenarioEscalates() {
        let scenario = simulator.generateScenario(type: .selfHarm)
        XCTAssertEqual(scenario.context.groundTruth.correctDecision, .escalate)
        XCTAssertEqual(scenario.context.groundTruth.severity, 0.95)
    }

    func testGamingScamBlocks() {
        let scenario = simulator.generateScenario(type: .gamingScam)
        XCTAssertEqual(scenario.context.groundTruth.correctDecision, .block)
    }

    func testUnauthorizedSpendAlerts() {
        let scenario = simulator.generateScenario(type: .unauthorizedSpend)
        XCTAssertEqual(scenario.context.groundTruth.correctDecision, .alert)
    }

    // MARK: - Threat Patterns

    func testThreatPatternsCount() {
        XCTAssertTrue(ThreatPatterns.totalCount >= 130, "Expected 130+ patterns, got \(ThreatPatterns.totalCount)")
    }

    func testGroomingPatterns() {
        XCTAssertEqual(ThreatPatterns.grooming.count, 29)
    }

    func testBullyingPatterns() {
        XCTAssertEqual(ThreatPatterns.bullying.count, 23)
    }

    func testGamingScamPatterns() {
        XCTAssertEqual(ThreatPatterns.gamingScam.count, 19)
    }

    func testPatternsForAllTypes() {
        for type in GuardianScenarioType.allCases {
            let patterns = ThreatPatterns.patterns(for: type)
            XCTAssertFalse(patterns.isEmpty, "No patterns for \(type)")
        }
    }

    // MARK: - Sender Generation

    func testEasyDifficultySenderIsNewAccount() {
        let scenario = simulator.generateScenario(type: .grooming, difficulty: .easy)
        let sender = scenario.context.senderInfo
        XCTAssertTrue(sender.accountAge.contains("day"), "Easy sender should have day-old account")
        XCTAssertEqual(sender.mutualConnections, 0)
    }

    func testHardDifficultySenderLooksLegitimate() {
        // Hard senders should look more legitimate
        let scenario = simulator.generateScenario(type: .grooming, difficulty: .hard)
        let sender = scenario.context.senderInfo
        XCTAssertTrue(sender.accountAge.contains("year"), "Hard sender should have year-old account")
        XCTAssertTrue(sender.mutualConnections >= 5)
    }
}
