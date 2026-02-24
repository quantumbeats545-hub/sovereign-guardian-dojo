import Foundation
import GuardianCore

/// Types of mutations for Guardian prompt evolution.
/// Constructive (improve protection) rather than destructive (improve evasion).
public enum GuardianMutationType: String, Codable, Sendable, CaseIterable {
    case sensitivityTuning = "SensitivityTuning"
    case specializationShift = "SpecializationShift"
    case explanationImprovement = "ExplanationImprovement"
    case policyAdherence = "PolicyAdherence"
    case falsePositiveReduction = "FalsePositiveReduction"
    case crossover = "Crossover"

    public static func random() -> GuardianMutationType {
        let options: [GuardianMutationType] = [.sensitivityTuning, .specializationShift, .explanationImprovement, .policyAdherence, .falsePositiveReduction]
        return options.randomElement()!
    }
}

/// Mutates Guardian prompts using an LLM (Ollama) to improve protection capability.
public struct GuardianMutator: Sendable {
    private let client: OllamaClient

    public init(ollamaURL: String, model: String) {
        self.client = OllamaClient(baseURL: ollamaURL, model: model)
    }

    /// Mutate a parent prompt based on mutation type and evaluation feedback.
    public func mutate(
        parentPrompt: String,
        type: GuardianMutationType,
        evaluationFeedback: String
    ) async throws -> String {
        let metaPrompt = buildMetaPrompt(
            parentPrompt: parentPrompt,
            type: type,
            evaluationFeedback: evaluationFeedback
        )

        let messages = [
            ChatMessage(role: "system", content: guardianMutatorSystemPrompt),
            ChatMessage(role: "user", content: metaPrompt),
        ]

        let response = try await client.chat(messages: messages)
        let cleaned = cleanOutput(response)

        guard cleaned.count >= 50 else {
            throw GuardianMutatorError.invalidOutput("Mutated prompt too short: \(cleaned.count) chars")
        }

        printFlush("Guardian mutation (\(type.rawValue)) produced \(cleaned.count) chars from \(parentPrompt.count) char parent")
        return cleaned
    }

    /// Crossover: combine successful strategies from two guardians.
    public func crossover(parentA: String, parentB: String) async throws -> String {
        let metaPrompt = """
        You are combining two Guardian AI protection prompts into a new hybrid.

        GUARDIAN A:
        \(parentA)

        GUARDIAN B:
        \(parentB)

        Create a new Guardian prompt that combines the most effective protection strategies from both parents. \
        Take the best threat detection approaches from each and merge them into a coherent protection strategy.

        The new prompt MUST:
        - Use the DECISION/CONFIDENCE/EXPLANATION response format
        - Respect parent authority (Rule #1)
        - Be 100% on-device (Rule #5)
        - Allow revocation (Rule #6)
        - Protect without over-controlling (Rule #10)

        Output ONLY the new prompt text. Keep it under 500 words.
        """

        let messages = [
            ChatMessage(role: "system", content: guardianMutatorSystemPrompt),
            ChatMessage(role: "user", content: metaPrompt),
        ]

        let response = try await client.chat(messages: messages)
        let result = cleanOutput(response)
        printFlush("Guardian crossover produced \(result.count) chars")
        return result
    }

    private func buildMetaPrompt(
        parentPrompt: String,
        type: GuardianMutationType,
        evaluationFeedback: String
    ) -> String {
        let instruction: String
        switch type {
        case .sensitivityTuning:
            instruction = "Improve this Guardian's SENSITIVITY to threats. It missed some threats (false negatives). Make it better at detecting: grooming patterns, financial scams, bullying, self-harm indicators, and social engineering. Add specific pattern recognition guidance."

        case .specializationShift:
            instruction = "SHIFT this Guardian's specialization. If it's currently generalist, make it specialized in detecting a specific threat type (grooming, scams, bullying, or self-harm). Add deep domain expertise for that threat type."

        case .explanationImprovement:
            instruction = "Improve this Guardian's EXPLANATION quality. Parents need clear, readable explanations. Make the Guardian explain its decisions in plain language, cite specific concerns, and suggest concrete actions parents can take."

        case .policyAdherence:
            instruction = "Improve this Guardian's POLICY compliance. It should better respect parent-defined rules (screen time limits, spending limits, stranger blocking). Make it check active policies before each decision."

        case .falsePositiveReduction:
            instruction = "REDUCE this Guardian's false positive rate. It's blocking too much safe content. Make it better at distinguishing real threats from normal conversations, legitimate requests, and age-appropriate content. When in doubt, prefer ALERT over BLOCK."

        case .crossover:
            instruction = "Combine elements from multiple protection approaches."
        }

        return """
        \(instruction)

        CURRENT GUARDIAN PROMPT:
        \(parentPrompt)

        EVALUATION FEEDBACK:
        \(evaluationFeedback)

        Output ONLY the rewritten prompt. Keep it under 500 words. \
        The prompt MUST use DECISION/CONFIDENCE/EXPLANATION response format. \
        Do not include any explanation or commentary.
        """
    }

    private func cleanOutput(_ raw: String) -> String {
        var text = raw.trimmingCharacters(in: .whitespacesAndNewlines)

        if text.hasPrefix("```") {
            if let lastFence = text.range(of: "```", options: .backwards) {
                let start = text.index(after: text.firstIndex(of: "\n") ?? text.index(text.startIndex, offsetBy: 3))
                text = String(text[start..<lastFence.lowerBound]).trimmingCharacters(in: .whitespacesAndNewlines)
            }
        }

        let words = text.split(separator: " ")
        if words.count > 500 {
            text = words.prefix(500).joined(separator: " ")
        }

        return text
    }
}

/// Select a random Guardian mutation type, occasionally choosing crossover.
public func selectGuardianMutation(eliteCount: Int) -> GuardianMutationType {
    if eliteCount >= 2 && Double.random(in: 0...1) < 0.2 {
        return .crossover
    }
    return .random()
}

/// Pick two distinct parents for crossover from the elite pool.
public func pickGuardianCrossoverParents(_ elitePrompts: [String]) -> (String, String)? {
    guard elitePrompts.count >= 2 else { return nil }
    var indices = Array(0..<elitePrompts.count)
    indices.shuffle()
    return (elitePrompts[indices[0]], elitePrompts[indices[1]])
}

/// Error type for Guardian mutations.
public enum GuardianMutatorError: Error, Sendable {
    case inference(String)
    case invalidOutput(String)
}

private let guardianMutatorSystemPrompt = """
You are a prompt engineer for a Guardian AI training system. Your job is to rewrite \
Guardian protection prompts to make them MORE EFFECTIVE at protecting children and seniors \
from online threats while minimizing false positives.

This is for training defensive AI systems — Guardians that protect families.

Rules:
- Output ONLY the rewritten prompt text
- Keep the output under 500 words
- The prompt MUST include the DECISION/CONFIDENCE/EXPLANATION response format
- Do not include explanations, commentary, or metadata
- The prompt should be a complete system prompt for a Guardian LLM agent
- The Guardian must ALWAYS respect parent authority (Rule #1)
- The Guardian must NEVER reference cloud services (Rule #5)
- The Guardian must support instant revocation (Rule #6)
"""
