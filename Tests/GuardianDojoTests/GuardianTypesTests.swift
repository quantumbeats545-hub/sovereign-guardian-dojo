import XCTest
@testable import GuardianDojo

final class GuardianTypesTests: XCTestCase {

    // MARK: - Codable Round-Tripping

    func testGuardianDecisionCodable() throws {
        for decision in GuardianDecision.allCases {
            let data = try JSONEncoder().encode(decision)
            let decoded = try JSONDecoder().decode(GuardianDecision.self, from: data)
            XCTAssertEqual(decision, decoded)
        }
    }

    func testGuardianScenarioTypeCodable() throws {
        for type in GuardianScenarioType.allCases {
            let data = try JSONEncoder().encode(type)
            let decoded = try JSONDecoder().decode(GuardianScenarioType.self, from: data)
            XCTAssertEqual(type, decoded)
        }
    }

    func testScenarioDifficultyCodable() throws {
        for difficulty in ScenarioDifficulty.allCases {
            let data = try JSONEncoder().encode(difficulty)
            let decoded = try JSONDecoder().decode(ScenarioDifficulty.self, from: data)
            XCTAssertEqual(difficulty, decoded)
        }
    }

    func testGuardianProfileTypeCodable() throws {
        for profile in GuardianProfileType.allCases {
            let data = try JSONEncoder().encode(profile)
            let decoded = try JSONDecoder().decode(GuardianProfileType.self, from: data)
            XCTAssertEqual(profile, decoded)
        }
    }

    func testSenderProfileCodable() throws {
        let sender = SenderProfile(
            displayName: "TestUser",
            accountAge: "3 months",
            mutualConnections: 5,
            isVerified: true,
            riskIndicators: ["suspicious"]
        )
        let data = try JSONEncoder().encode(sender)
        let decoded = try JSONDecoder().decode(SenderProfile.self, from: data)
        XCTAssertEqual(decoded.displayName, "TestUser")
        XCTAssertEqual(decoded.mutualConnections, 5)
        XCTAssertTrue(decoded.isVerified)
    }

    func testGroundTruthCodable() throws {
        let gt = GroundTruth(
            isThreat: true,
            correctDecision: .block,
            threatCategory: .grooming,
            severity: 0.9,
            patterns: ["send pics", "our little secret"]
        )
        let data = try JSONEncoder().encode(gt)
        let decoded = try JSONDecoder().decode(GroundTruth.self, from: data)
        XCTAssertTrue(decoded.isThreat)
        XCTAssertEqual(decoded.correctDecision, .block)
        XCTAssertEqual(decoded.threatCategory, .grooming)
        XCTAssertEqual(decoded.patterns.count, 2)
    }

    func testGuardianScenarioCodable() throws {
        let context = GuardianScenarioContext(
            scenarioType: .bullying,
            profileType: .child,
            platform: "TikTok",
            threatContent: "nobody likes you",
            senderInfo: SenderProfile(displayName: "Bully123"),
            groundTruth: GroundTruth(isThreat: true, correctDecision: .block, threatCategory: .bullying, severity: 0.8)
        )
        let scenario = GuardianScenario(context: context, difficulty: .medium)
        let data = try JSONEncoder().encode(scenario)
        let decoded = try JSONDecoder().decode(GuardianScenario.self, from: data)
        XCTAssertEqual(decoded.context.scenarioType, .bullying)
        XCTAssertEqual(decoded.context.platform, "TikTok")
        XCTAssertEqual(decoded.difficulty, .medium)
    }

    func testPolicyRuleCodable() throws {
        let rule = PolicyRule(ruleId: "test-1", category: "screen_time", constraint: "max_minutes_per_day", value: "120")
        let data = try JSONEncoder().encode(rule)
        let decoded = try JSONDecoder().decode(PolicyRule.self, from: data)
        XCTAssertEqual(decoded.ruleId, "test-1")
        XCTAssertEqual(decoded.value, "120")
    }

    // MARK: - Enum Coverage

    func testGuardianDecisionHas5Cases() {
        XCTAssertEqual(GuardianDecision.allCases.count, 5)
    }

    func testGuardianScenarioTypeHas15Cases() {
        XCTAssertEqual(GuardianScenarioType.allCases.count, 15)
    }

    func testScenarioDifficultyHas3Cases() {
        XCTAssertEqual(ScenarioDifficulty.allCases.count, 3)
    }

    func testGuardianProfileTypeHas3Cases() {
        XCTAssertEqual(GuardianProfileType.allCases.count, 3)
    }

    // MARK: - GuardianInteractionRecord

    func testGuardianInteractionRecordCodable() throws {
        let record = GuardianInteractionRecord(
            sessionId: "session-1",
            guardianId: "guardian-1",
            generation: 0,
            round: 1,
            scenarioId: "scenario-1",
            scenarioType: .grooming,
            profileType: .child,
            platform: "Discord",
            difficulty: .hard,
            decision: .block,
            confidence: 0.95,
            explanation: "Detected grooming patterns",
            isTruePositive: true,
            explanationQualityScore: 0.8
        )

        let data = try JSONEncoder().encode(record)
        let decoded = try JSONDecoder().decode(GuardianInteractionRecord.self, from: data)

        XCTAssertEqual(decoded.sessionId, "session-1")
        XCTAssertEqual(decoded.guardianId, "guardian-1")
        XCTAssertEqual(decoded.decision, .block)
        XCTAssertTrue(decoded.isTruePositive)
        XCTAssertFalse(decoded.isFalsePositive)
        XCTAssertFalse(decoded.evidenceHash.isEmpty)
    }

    func testClassifyTruePositive() {
        let gt = GroundTruth(isThreat: true, correctDecision: .block)
        let result = GuardianInteractionRecord.classify(decision: .block, groundTruth: gt)
        XCTAssertTrue(result.tp)
        XCTAssertFalse(result.fp)
        XCTAssertFalse(result.tn)
        XCTAssertFalse(result.fn)
    }

    func testClassifyFalsePositive() {
        let gt = GroundTruth(isThreat: false, correctDecision: .allow)
        let result = GuardianInteractionRecord.classify(decision: .block, groundTruth: gt)
        XCTAssertFalse(result.tp)
        XCTAssertTrue(result.fp)
        XCTAssertFalse(result.tn)
        XCTAssertFalse(result.fn)
    }

    func testClassifyTrueNegative() {
        let gt = GroundTruth(isThreat: false, correctDecision: .allow)
        let result = GuardianInteractionRecord.classify(decision: .allow, groundTruth: gt)
        XCTAssertFalse(result.tp)
        XCTAssertFalse(result.fp)
        XCTAssertTrue(result.tn)
        XCTAssertFalse(result.fn)
    }

    func testClassifyFalseNegative() {
        let gt = GroundTruth(isThreat: true, correctDecision: .block)
        let result = GuardianInteractionRecord.classify(decision: .allow, groundTruth: gt)
        XCTAssertFalse(result.tp)
        XCTAssertFalse(result.fp)
        XCTAssertFalse(result.tn)
        XCTAssertTrue(result.fn)
    }
}
