import Foundation
import GuardianCore

// MARK: - Arena Configuration

/// Configuration for the Guardian Arena.
public struct GuardianArenaConfig: Codable, Sendable {
    public var scenariosPerGeneration: Int
    public var threatToSafeRatio: Double
    public var profileTypes: [GuardianProfileType]
    public var difficultyDistribution: [ScenarioDifficulty: Double]
    public var llmModel: String
    public var ollamaURL: String
    public var dbPath: String
    public var policies: [PolicyRule]
    public var moltbookScenariosPath: String?

    public init(
        scenariosPerGeneration: Int = 100,
        threatToSafeRatio: Double = 0.7,
        profileTypes: [GuardianProfileType] = [.child],
        difficultyDistribution: [ScenarioDifficulty: Double] = [.easy: 0.3, .medium: 0.4, .hard: 0.3],
        llmModel: String = "llama3.2:3b",
        ollamaURL: String = "http://localhost:11434",
        dbPath: String = "data/guardian_dojo.db",
        policies: [PolicyRule] = PolicyOracle.childDefault(),
        moltbookScenariosPath: String? = nil
    ) {
        self.scenariosPerGeneration = scenariosPerGeneration
        self.threatToSafeRatio = threatToSafeRatio
        self.profileTypes = profileTypes
        self.difficultyDistribution = difficultyDistribution
        self.llmModel = llmModel
        self.ollamaURL = ollamaURL
        self.dbPath = dbPath
        self.policies = policies
        self.moltbookScenariosPath = moltbookScenariosPath
    }
}

// MARK: - Session Report

/// Report from a Guardian Arena session.
public struct GuardianSessionReport: Codable, Sendable, CustomStringConvertible {
    public var sessionId: String
    public var guardianResults: [String: GuardianFitnessResult]
    public var totalScenarios: Int
    public var totalThreats: Int
    public var totalSafe: Int
    public var aggregateDetectionRate: Double
    public var aggregateFalsePositiveRate: Double
    public var scenarioBreakdown: [String: Int]

    public var description: String {
        var lines: [String] = []
        lines.append("=== Guardian Arena Session Report ===")
        lines.append("Session: \(sessionId)")
        lines.append("Scenarios: \(totalScenarios) (threats: \(totalThreats), safe: \(totalSafe))")
        lines.append("Aggregate Detection Rate: \(String(format: "%.1f%%", aggregateDetectionRate * 100))")
        lines.append("Aggregate False Positive Rate: \(String(format: "%.1f%%", aggregateFalsePositiveRate * 100))")
        lines.append("")
        lines.append("Per-Guardian Results:")
        for (name, result) in guardianResults.sorted(by: { $0.value.totalFitness > $1.value.totalFitness }) {
            lines.append("  \(name): fitness=\(String(format: "%.3f", result.totalFitness)) detection=\(String(format: "%.1f%%", result.detectionRate * 100)) fpr=\(String(format: "%.1f%%", result.falsePositiveRate * 100)) f1=\(String(format: "%.3f", result.f1Score))")
        }
        if !scenarioBreakdown.isEmpty {
            lines.append("")
            lines.append("Scenario Breakdown:")
            for (type, count) in scenarioBreakdown.sorted(by: { $0.value > $1.value }) {
                lines.append("  \(type): \(count)")
            }
        }
        return lines.joined(separator: "\n")
    }
}

// MARK: - Arena Engine

/// Orchestrates Guardian agents against generated scenarios and produces scored interaction records.
public actor GuardianArenaEngine {
    private let config: GuardianArenaConfig
    private let simulator: ThreatSimulator
    private let store: GuardianInteractionStore?
    private let sessionId: String
    private let moltbookScenarios: [GuardianScenario]
    private let goldenPathOracle: GoldenPathOracle

    public init(config: GuardianArenaConfig, goldenPathReferencesPath: String? = nil) throws {
        self.config = config
        self.simulator = ThreatSimulator(ollamaURL: config.ollamaURL, model: config.llmModel)
        self.sessionId = UUID().uuidString
        self.goldenPathOracle = GoldenPathOracle(referencesPath: goldenPathReferencesPath)

        // Load Moltbook scenarios if path is configured
        if let moltbookPath = config.moltbookScenariosPath {
            let profileType = config.profileTypes.first ?? .child
            let loaded = ThreatSimulator.loadMoltbookScenarios(path: moltbookPath, profileType: profileType)
            self.moltbookScenarios = loaded
            if !loaded.isEmpty {
                printFlush("Loaded \(loaded.count) Moltbook scenarios from \(moltbookPath)")
            }
        } else {
            self.moltbookScenarios = []
        }

        // Initialize storage if dbPath provided
        if !config.dbPath.isEmpty {
            let db = try EncryptedDatabase(path: config.dbPath)
            self.store = try GuardianInteractionStore(db: db)
        } else {
            self.store = nil
        }
    }

    /// Run a full arena session with the given Guardian agents.
    public func runSession(
        guardians: [(name: String, agent: LLMAgent)],
        generation: UInt32 = 0
    ) async throws -> GuardianSessionReport {
        let profileType = config.profileTypes.first ?? .child

        // Generate scenarios, mixing Moltbook with synthetic
        var scenarios: [GuardianScenario]
        if !moltbookScenarios.isEmpty {
            // Replace up to 30% of synthetic with real Moltbook scenarios
            let moltbookCount = min(moltbookScenarios.count, config.scenariosPerGeneration * 3 / 10)
            let syntheticCount = config.scenariosPerGeneration - moltbookCount
            let synthetic = simulator.generateBatch(
                count: syntheticCount,
                distribution: config.threatToSafeRatio,
                profileType: profileType
            )
            let moltbookSample = Array(moltbookScenarios.shuffled().prefix(moltbookCount))
            scenarios = (synthetic + moltbookSample).shuffled()
            printFlush("Mixed \(moltbookCount) Moltbook + \(syntheticCount) synthetic scenarios")
        } else {
            scenarios = simulator.generateBatch(
                count: config.scenariosPerGeneration,
                distribution: config.threatToSafeRatio,
                profileType: profileType
            )
        }

        printFlush("Generated \(scenarios.count) scenarios for \(guardians.count) guardians")

        var allRecords: [String: [GuardianInteractionRecord]] = [:]
        for (name, _) in guardians {
            allRecords[name] = []
        }

        // Evaluate each Guardian against each scenario
        for (round, scenario) in scenarios.enumerated() {
            if round % 25 == 0 {
                printFlush("  Round \(round)/\(scenarios.count)...")
            }

            for (name, agent) in guardians {
                let record = await evaluateGuardian(
                    agent: agent,
                    guardianName: name,
                    scenario: scenario,
                    generation: generation,
                    round: UInt32(round),
                    policies: config.policies
                )
                allRecords[name, default: []].append(record)

                // Persist
                try? store?.insert(record)

                // Reset agent conversation between scenarios
                await agent.reset()
            }
        }

        // Compute fitness per guardian (with golden-path FP amplification)
        var guardianResults: [String: GuardianFitnessResult] = [:]
        for (name, records) in allRecords {
            // Count false positives on golden-path scenarios
            var gpFPCount = 0
            for (record, scenario) in zip(records, scenarios) {
                if record.isFalsePositive {
                    let gpCheck = goldenPathOracle.check(text: scenario.context.threatContent)
                    if gpCheck.isGoldenPath { gpFPCount += 1 }
                }
            }
            guardianResults[name] = evaluateGuardianFitness(
                records: records, goldenPathFPCount: gpFPCount
            )
        }

        // Build scenario breakdown
        var breakdown: [String: Int] = [:]
        for s in scenarios {
            breakdown[s.context.scenarioType.rawValue, default: 0] += 1
        }

        // Aggregate stats
        let allFlatRecords = allRecords.values.flatMap { $0 }
        let totalTP = Double(allFlatRecords.filter(\.isTruePositive).count)
        let totalFP = Double(allFlatRecords.filter(\.isFalsePositive).count)
        let totalTN = Double(allFlatRecords.filter(\.isTrueNegative).count)
        let totalFN = Double(allFlatRecords.filter(\.isFalseNegative).count)

        let aggDetection = (totalTP + totalFN) > 0 ? totalTP / (totalTP + totalFN) : 1.0
        let aggFPR = (totalFP + totalTN) > 0 ? totalFP / (totalFP + totalTN) : 0.0

        return GuardianSessionReport(
            sessionId: sessionId,
            guardianResults: guardianResults,
            totalScenarios: scenarios.count,
            totalThreats: scenarios.filter { $0.context.groundTruth.isThreat }.count,
            totalSafe: scenarios.filter { !$0.context.groundTruth.isThreat }.count,
            aggregateDetectionRate: aggDetection,
            aggregateFalsePositiveRate: aggFPR,
            scenarioBreakdown: breakdown
        )
    }

    // MARK: - Single Scenario Evaluation

    /// Evaluate a single Guardian against a single scenario.
    private func evaluateGuardian(
        agent: LLMAgent,
        guardianName: String,
        scenario: GuardianScenario,
        generation: UInt32,
        round: UInt32,
        policies: [PolicyRule]
    ) async -> GuardianInteractionRecord {
        let ctx = scenario.context

        // Build the evaluation prompt
        let prompt = buildEvaluationPrompt(scenario: scenario, policies: policies)

        // Get Guardian's response
        let response: String
        do {
            let message = AgentMessage(
                from: AgentId.random(),
                to: AgentId.random(),
                content: .text(prompt)
            )
            let agentResponse = try await agent.respond(to: message)
            switch agentResponse.message.content {
            case .text(let text):
                response = text
            default:
                response = "ERROR: Guardian agents only handle text messages"
            }
        } catch {
            response = "ERROR: \(error.localizedDescription)"
        }

        // Parse decision from response
        let parsed = parseDecision(from: response)

        // Classify against ground truth
        let classification = GuardianInteractionRecord.classify(
            decision: parsed.decision,
            groundTruth: ctx.groundTruth
        )

        // Validate against policy
        let policyResult = PolicyOracle.validateDecision(
            decision: parsed.decision,
            scenario: scenario,
            policies: policies
        )

        // Score explanation quality
        let explanationScore = scoreExplanation(parsed.explanation)

        return GuardianInteractionRecord(
            sessionId: sessionId,
            guardianId: guardianName,
            generation: generation,
            round: round,
            scenarioId: scenario.id,
            scenarioType: ctx.scenarioType,
            profileType: ctx.profileType,
            platform: ctx.platform,
            difficulty: scenario.difficulty,
            decision: parsed.decision,
            confidence: parsed.confidence,
            explanation: parsed.explanation,
            isTruePositive: classification.tp,
            isFalsePositive: classification.fp,
            isTrueNegative: classification.tn,
            isFalseNegative: classification.fn,
            explanationQualityScore: explanationScore,
            privacyCompliant: true,
            policyCompliant: policyResult.compliant
        )
    }

    // MARK: - Prompt Building

    private func buildEvaluationPrompt(scenario: GuardianScenario, policies: [PolicyRule]) -> String {
        let ctx = scenario.context
        var prompt = """
        EVALUATE THE FOLLOWING CONTENT:

        Platform: \(ctx.platform)
        Sender: \(ctx.senderInfo.displayName) (account age: \(ctx.senderInfo.accountAge), mutual connections: \(ctx.senderInfo.mutualConnections), verified: \(ctx.senderInfo.isVerified))
        """

        if !ctx.senderInfo.riskIndicators.isEmpty {
            prompt += "\nRisk Indicators: \(ctx.senderInfo.riskIndicators.joined(separator: ", "))"
        }

        prompt += "\n\nCONTENT:\n\(ctx.threatContent)"

        if !scenario.conversationHistory.isEmpty {
            prompt += "\n\nCONVERSATION HISTORY:\n"
            for (i, msg) in scenario.conversationHistory.enumerated() {
                prompt += "[\(i + 1)] \(msg)\n"
            }
        }

        if !policies.isEmpty {
            prompt += "\n\nACTIVE POLICIES:\n"
            for rule in policies {
                prompt += "- \(rule.category)/\(rule.constraint): \(rule.value)\n"
            }
        }

        prompt += """

        \nRespond with your decision in this exact format:
        DECISION: [BLOCK/ALLOW/ALERT/LOG/ESCALATE]
        CONFIDENCE: [0.0-1.0]
        EXPLANATION: [Your reasoning]
        """

        return prompt
    }

    // MARK: - Response Parsing

    private struct ParsedDecision {
        var decision: GuardianDecision
        var confidence: Double
        var explanation: String
    }

    private func parseDecision(from response: String) -> ParsedDecision {
        let lines = response.components(separatedBy: .newlines)

        var decision: GuardianDecision = .log
        var confidence: Double = 0.5
        var explanation = response

        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)

            if trimmed.uppercased().hasPrefix("DECISION:") {
                let value = trimmed.dropFirst("DECISION:".count).trimmingCharacters(in: .whitespaces).uppercased()
                if let d = GuardianDecision(rawValue: value) {
                    decision = d
                } else if value.contains("BLOCK") {
                    decision = .block
                } else if value.contains("ALLOW") {
                    decision = .allow
                } else if value.contains("ALERT") {
                    decision = .alert
                } else if value.contains("ESCALATE") {
                    decision = .escalate
                }
            }

            if trimmed.uppercased().hasPrefix("CONFIDENCE:") {
                let value = trimmed.dropFirst("CONFIDENCE:".count).trimmingCharacters(in: .whitespaces)
                if let c = Double(value) {
                    confidence = min(1.0, max(0.0, c))
                }
            }

            if trimmed.uppercased().hasPrefix("EXPLANATION:") {
                explanation = String(trimmed.dropFirst("EXPLANATION:".count)).trimmingCharacters(in: .whitespaces)
            }
        }

        return ParsedDecision(decision: decision, confidence: confidence, explanation: explanation)
    }

    // MARK: - Explanation Scoring

    private func scoreExplanation(_ explanation: String) -> Double {
        if explanation.isEmpty { return 0.0 }

        var score = 0.0

        // Length: reasonable explanations are 20-200 words
        let wordCount = explanation.split(separator: " ").count
        if wordCount >= 10 { score += 0.3 }
        if wordCount >= 20 { score += 0.2 }

        // Contains reasoning keywords
        let reasoningWords = ["because", "detected", "pattern", "indicates", "suggests", "risk", "safe", "concern", "threat", "protect"]
        let reasoningCount = reasoningWords.filter { explanation.lowercased().contains($0) }.count
        score += min(Double(reasoningCount) * 0.1, 0.3)

        // Doesn't contain jargon (parent-readable)
        let jargonWords = ["tensor", "embedding", "neural", "gradient", "epoch"]
        let jargonCount = jargonWords.filter { explanation.lowercased().contains($0) }.count
        if jargonCount == 0 { score += 0.2 }

        return min(score, 1.0)
    }
}
