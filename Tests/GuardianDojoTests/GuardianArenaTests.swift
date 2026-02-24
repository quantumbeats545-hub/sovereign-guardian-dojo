import XCTest
@testable import GuardianDojo
import GuardianCore

final class GuardianArenaTests: XCTestCase {

    // MARK: - Arena Config

    func testDefaultArenaConfig() {
        let config = GuardianArenaConfig()
        XCTAssertEqual(config.scenariosPerGeneration, 100)
        XCTAssertEqual(config.threatToSafeRatio, 0.7)
        XCTAssertEqual(config.profileTypes, [.child])
        XCTAssertEqual(config.llmModel, "llama3.2:3b")
        XCTAssertFalse(config.policies.isEmpty)
    }

    func testCustomArenaConfig() {
        let config = GuardianArenaConfig(
            scenariosPerGeneration: 50,
            threatToSafeRatio: 0.5,
            profileTypes: [.child, .senior],
            llmModel: "qwen2.5:7b",
            dbPath: "data/test_guardian.db"
        )
        XCTAssertEqual(config.scenariosPerGeneration, 50)
        XCTAssertEqual(config.threatToSafeRatio, 0.5)
        XCTAssertEqual(config.profileTypes.count, 2)
    }

    // MARK: - Session Report

    func testSessionReportDescription() {
        let report = GuardianSessionReport(
            sessionId: "test-session",
            guardianResults: [
                "guardian-1": GuardianFitnessResult(
                    totalFitness: 0.85,
                    detectionRate: 0.95,
                    falsePositiveRate: 0.05,
                    precision: 0.93,
                    recall: 0.95,
                    f1Score: 0.94,
                    privacyScore: 1.0,
                    revocationScore: 1.0,
                    explanationScore: 0.7,
                    policyScore: 1.0,
                    scenariosEvaluated: 100
                )
            ],
            totalScenarios: 100,
            totalThreats: 70,
            totalSafe: 30,
            aggregateDetectionRate: 0.95,
            aggregateFalsePositiveRate: 0.05,
            scenarioBreakdown: ["grooming": 10, "bullying": 10]
        )

        let desc = report.description
        XCTAssertTrue(desc.contains("Guardian Arena Session Report"))
        XCTAssertTrue(desc.contains("guardian-1"))
        XCTAssertTrue(desc.contains("95.0%"))
    }

    // MARK: - Agent Factory

    func testGuardianAgentFactoryCreatesDefender() {
        let agent = GuardianAgentFactory.defender(
            name: "test-guardian",
            model: "llama3.2:3b",
            ollamaURL: "http://localhost:11434"
        )
        XCTAssertNotNil(agent)
    }

    func testGuardianAgentFactoryWithCustomPrompt() {
        let customPrompt = "You are a custom guardian."
        let agent = GuardianAgentFactory.withPrompt(
            name: "custom-guardian",
            prompt: customPrompt,
            model: "llama3.2:3b",
            ollamaURL: "http://localhost:11434"
        )
        XCTAssertNotNil(agent)
    }

    func testThreatAgentFactories() {
        let groomer = ThreatAgentFactory.groomer(model: "llama3.2:3b", ollamaURL: "http://localhost:11434")
        let scammer = ThreatAgentFactory.scammer(model: "llama3.2:3b", ollamaURL: "http://localhost:11434")
        let bully = ThreatAgentFactory.bully(model: "llama3.2:3b", ollamaURL: "http://localhost:11434")
        let peer = ThreatAgentFactory.benignPeer(model: "llama3.2:3b", ollamaURL: "http://localhost:11434")

        XCTAssertNotNil(groomer)
        XCTAssertNotNil(scammer)
        XCTAssertNotNil(bully)
        XCTAssertNotNil(peer)
    }

    // MARK: - Base Defender Prompt

    func testDefenderPromptContainsRules() {
        let prompt = GuardianAgentFactory.baseDefenderPrompt(profileType: .child)
        XCTAssertTrue(prompt.contains("child"))
        XCTAssertTrue(prompt.contains("BLOCK"))
        XCTAssertTrue(prompt.contains("ALLOW"))
        XCTAssertTrue(prompt.contains("ALERT"))
        XCTAssertTrue(prompt.contains("ESCALATE"))
        XCTAssertTrue(prompt.contains("parent"))
    }

    func testDefenderPromptVariesByProfile() {
        let childPrompt = GuardianAgentFactory.baseDefenderPrompt(profileType: .child)
        let seniorPrompt = GuardianAgentFactory.baseDefenderPrompt(profileType: .senior)
        XCTAssertTrue(childPrompt.contains("child"))
        XCTAssertTrue(seniorPrompt.contains("senior"))
    }

    // MARK: - Storage

    func testGuardianStorageInsertAndRetrieve() throws {
        let db = try EncryptedDatabase()
        let store = try GuardianInteractionStore(db: db)

        let record = GuardianInteractionRecord(
            sessionId: "test-session",
            guardianId: "guardian-1",
            generation: 0,
            round: 0,
            scenarioId: "scenario-1",
            scenarioType: .grooming,
            profileType: .child,
            platform: "Discord",
            difficulty: .medium,
            decision: .block,
            confidence: 0.95,
            explanation: "Detected grooming pattern",
            isTruePositive: true,
            explanationQualityScore: 0.8
        )

        try store.insert(record)

        let all = try store.getAll()
        XCTAssertEqual(all.count, 1)
        XCTAssertEqual(all[0].decision, .block)
        XCTAssertEqual(all[0].guardianId, "guardian-1")
    }

    func testGuardianStorageCountByDecision() throws {
        let db = try EncryptedDatabase()
        let store = try GuardianInteractionStore(db: db)

        for i in 0..<5 {
            let record = GuardianInteractionRecord(
                sessionId: "test",
                guardianId: "g1",
                generation: 0,
                round: UInt32(i),
                scenarioId: "s-\(i)",
                scenarioType: .grooming,
                profileType: .child,
                platform: "Discord",
                difficulty: .easy,
                decision: i < 3 ? .block : .allow,
                confidence: 0.9,
                explanation: "test"
            )
            try store.insert(record)
        }

        let blockCount = try store.countByDecision(.block)
        let allowCount = try store.countByDecision(.allow)
        XCTAssertEqual(blockCount, 3)
        XCTAssertEqual(allowCount, 2)
    }

    func testGuardianStorageGetByGuardian() throws {
        let db = try EncryptedDatabase()
        let store = try GuardianInteractionStore(db: db)

        for i in 0..<3 {
            let record = GuardianInteractionRecord(
                sessionId: "test",
                guardianId: "guardian-A",
                generation: 0,
                round: UInt32(i),
                scenarioId: "s-A-\(i)",
                scenarioType: .bullying,
                profileType: .child,
                platform: "TikTok",
                difficulty: .medium,
                decision: .block,
                confidence: 0.8,
                explanation: "test"
            )
            try store.insert(record)
        }

        for i in 0..<2 {
            let record = GuardianInteractionRecord(
                sessionId: "test",
                guardianId: "guardian-B",
                generation: 0,
                round: UInt32(i),
                scenarioId: "s-B-\(i)",
                scenarioType: .phishing,
                profileType: .senior,
                platform: "Email",
                difficulty: .easy,
                decision: .alert,
                confidence: 0.7,
                explanation: "test"
            )
            try store.insert(record)
        }

        let aRecords = try store.getByGuardian("guardian-A")
        let bRecords = try store.getByGuardian("guardian-B")
        XCTAssertEqual(aRecords.count, 3)
        XCTAssertEqual(bRecords.count, 2)
    }
}
