import XCTest
@testable import GuardianDojo

final class GuardianEvolutionTests: XCTestCase {

    // MARK: - Configuration

    func testDefaultEvolutionConfig() {
        let config = GuardianEvolutionConfig()
        XCTAssertEqual(config.generations, 10)
        XCTAssertEqual(config.populationSize, 6)
        XCTAssertEqual(config.eliteFraction, 0.33)
        XCTAssertEqual(config.scenariosPerGeneration, 100)
    }

    func testDefaultGraduationCriteria() {
        let criteria = GuardianGraduationCriteria()
        XCTAssertEqual(criteria.minDetectionRate, 0.95)
        XCTAssertEqual(criteria.maxFalsePositiveRate, 0.05)
        XCTAssertEqual(criteria.minRevocationScore, 1.0)
        XCTAssertEqual(criteria.minExplanationScore, 0.70)
        XCTAssertEqual(criteria.minGenerations, 5)
    }

    // MARK: - Lineage Store

    func testGuardianLineageStoreAddPrompt() {
        var store = GuardianLineageStore()
        let prompt = EvolvedGuardianPrompt.seed(
            text: "Test guardian prompt",
            specialization: .generalProtector
        )
        store.addPrompt(prompt)
        XCTAssertEqual(store.prompts.count, 1)
        XCTAssertEqual(store.prompts[0].specialization, .generalProtector)
    }

    func testGuardianLineageStoreAddGeneration() {
        var store = GuardianLineageStore()
        let summary = GuardianGenerationSummary(
            generation: 0,
            populationSize: 6,
            bestFitness: 0.85,
            avgFitness: 0.72,
            bestDetectionRate: 0.95,
            bestFalsePositiveRate: 0.04,
            distinctSpecializations: 3,
            specializationCounts: ["GeneralProtector": 2, "GroomingSpecialist": 2, "ScamDetector": 2]
        )
        store.addGeneration(summary)
        XCTAssertEqual(store.generations.count, 1)
        XCTAssertEqual(store.generations[0].generation, 0)
    }

    func testGuardianLineagePromptsForGeneration() {
        var store = GuardianLineageStore()
        for gen in 0..<3 as Range<UInt32> {
            let prompt = EvolvedGuardianPrompt.seed(
                text: "Prompt for gen \(gen) - \(UUID().uuidString)",
                specialization: .generalProtector
            )
            var p = prompt
            p.generation = gen
            store.addPrompt(p)
        }

        let gen0 = store.promptsForGeneration(0)
        let gen1 = store.promptsForGeneration(1)
        XCTAssertEqual(gen0.count, 1)
        XCTAssertEqual(gen1.count, 1)
    }

    func testGuardianLineageSaveAndLoad() throws {
        var store = GuardianLineageStore()
        store.addPrompt(EvolvedGuardianPrompt.seed(text: "Test prompt \(UUID())", specialization: .scamDetector))

        let tmpPath = NSTemporaryDirectory() + "guardian_lineage_test_\(UUID().uuidString).json"
        try store.save(to: tmpPath)

        let loaded = try GuardianLineageStore.load(from: tmpPath)
        XCTAssertEqual(loaded.prompts.count, 1)
        XCTAssertEqual(loaded.prompts[0].specialization, .scamDetector)

        try? FileManager.default.removeItem(atPath: tmpPath)
    }

    // MARK: - Prompt ID

    func testGuardianPromptIdDeterministic() {
        let text = "Test prompt text for hashing"
        let id1 = GuardianPromptId(fromPrompt: text)
        let id2 = GuardianPromptId(fromPrompt: text)
        XCTAssertEqual(id1, id2)
    }

    func testGuardianPromptIdDiffersForDifferentText() {
        let id1 = GuardianPromptId(fromPrompt: "Prompt A")
        let id2 = GuardianPromptId(fromPrompt: "Prompt B")
        XCTAssertNotEqual(id1, id2)
    }

    // MARK: - Specialization

    func testAllSpecializations() {
        XCTAssertEqual(GuardianSpecialization.allCases.count, 6)
    }

    func testSpecializationCodable() throws {
        for spec in GuardianSpecialization.allCases {
            let data = try JSONEncoder().encode(spec)
            let decoded = try JSONDecoder().decode(GuardianSpecialization.self, from: data)
            XCTAssertEqual(spec, decoded)
        }
    }

    // MARK: - Mutation Types

    func testAllMutationTypes() {
        XCTAssertEqual(GuardianMutationType.allCases.count, 6)
    }

    func testRandomMutationExcludesCrossover() {
        // Run multiple times to verify crossover is excluded from random()
        for _ in 0..<100 {
            let mutation = GuardianMutationType.random()
            XCTAssertNotEqual(mutation, .crossover)
        }
    }

    func testSelectGuardianMutationWithFewElites() {
        // With 1 elite, crossover should never be selected
        for _ in 0..<100 {
            let mutation = selectGuardianMutation(eliteCount: 1)
            XCTAssertNotEqual(mutation, .crossover)
        }
    }

    // MARK: - Graduated Guardian

    func testGraduatedGuardianCodable() throws {
        let fitness = GuardianFitnessResult(
            totalFitness: 0.92,
            detectionRate: 0.96,
            falsePositiveRate: 0.03,
            precision: 0.95,
            recall: 0.96,
            f1Score: 0.955,
            privacyScore: 1.0,
            revocationScore: 1.0,
            explanationScore: 0.85,
            policyScore: 1.0,
            scenariosEvaluated: 100
        )

        let graduated = GraduatedGuardian(
            id: "test-id",
            name: "Guardian-General-Gen5",
            systemPrompt: "Test prompt",
            fitness: fitness,
            generation: 5,
            specializations: [.generalProtector, .groomingSpecialist]
        )

        let data = try JSONEncoder().encode(graduated)
        let decoded = try JSONDecoder().decode(GraduatedGuardian.self, from: data)
        XCTAssertEqual(decoded.name, "Guardian-General-Gen5")
        XCTAssertEqual(decoded.specializations.count, 2)
        XCTAssertEqual(decoded.fitness.detectionRate, 0.96)
    }

    // MARK: - Evolution Report

    func testEvolutionReportDescription() {
        let report = GuardianEvolutionReport(
            generationsRun: 10,
            graduatedGuardians: [],
            fitnessHistory: [
                ["bestFitness": 0.5, "avgFitness": 0.4, "bestDetection": 0.6],
                ["bestFitness": 0.7, "avgFitness": 0.6, "bestDetection": 0.8],
            ],
            graduated: false
        )

        let desc = report.description
        XCTAssertTrue(desc.contains("Guardian Evolution Report"))
        XCTAssertTrue(desc.contains("Generations run: 10"))
        XCTAssertTrue(desc.contains("Graduated: NO"))
    }
}
