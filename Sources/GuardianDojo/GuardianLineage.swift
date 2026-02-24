import Foundation
import CryptoKit
import GuardianCore

/// Content-addressed Guardian prompt identifier.
public struct GuardianPromptId: Codable, Sendable, Hashable, Equatable, CustomStringConvertible {
    public let hash: String

    public init(fromPrompt text: String) {
        let digest = SHA256.hash(data: Data(text.utf8))
        self.hash = digest.map { String(format: "%02x", $0) }.joined()
    }

    public var description: String { String(hash.prefix(12)) }
}

/// A Guardian prompt that has been evolved through the training loop.
public struct EvolvedGuardianPrompt: Codable, Sendable {
    public var id: GuardianPromptId
    public var generation: UInt32
    public var parentId: GuardianPromptId?
    public var promptText: String
    public var specialization: GuardianSpecialization
    public var fitness: Double
    public var detectionRate: Double
    public var falsePositiveRate: Double
    public var mutationDescription: String

    public static func seed(text: String, specialization: GuardianSpecialization) -> EvolvedGuardianPrompt {
        EvolvedGuardianPrompt(
            id: GuardianPromptId(fromPrompt: text),
            generation: 0,
            parentId: nil,
            promptText: text,
            specialization: specialization,
            fitness: 0,
            detectionRate: 0,
            falsePositiveRate: 1.0,
            mutationDescription: "seed prompt"
        )
    }

    public static func evolved(
        generation: UInt32,
        parentId: GuardianPromptId,
        promptText: String,
        specialization: GuardianSpecialization,
        mutationDescription: String
    ) -> EvolvedGuardianPrompt {
        EvolvedGuardianPrompt(
            id: GuardianPromptId(fromPrompt: promptText),
            generation: generation,
            parentId: parentId,
            promptText: promptText,
            specialization: specialization,
            fitness: 0,
            detectionRate: 0,
            falsePositiveRate: 1.0,
            mutationDescription: mutationDescription
        )
    }
}

/// Guardian specialization types.
public enum GuardianSpecialization: String, Codable, Sendable, CaseIterable {
    case generalProtector = "GeneralProtector"
    case groomingSpecialist = "GroomingSpecialist"
    case scamDetector = "ScamDetector"
    case contentFilter = "ContentFilter"
    case seniorProtector = "SeniorProtector"
    case bullyingDetector = "BullyingDetector"
}

/// Summary of a Guardian generation's results.
public struct GuardianGenerationSummary: Codable, Sendable {
    public var generation: UInt32
    public var populationSize: Int
    public var bestFitness: Double
    public var avgFitness: Double
    public var bestDetectionRate: Double
    public var bestFalsePositiveRate: Double
    public var distinctSpecializations: Int
    public var specializationCounts: [String: Int]
    public var monocultureEvents: [String]?
}

/// Stores the complete lineage of evolved Guardian prompts across generations.
public struct GuardianLineageStore: Codable, Sendable {
    public var prompts: [EvolvedGuardianPrompt]
    public var generations: [GuardianGenerationSummary]

    public init() {
        self.prompts = []
        self.generations = []
    }

    public mutating func addPrompt(_ prompt: EvolvedGuardianPrompt) {
        printFlush("Guardian Lineage: gen=\(prompt.generation) id=\(prompt.id) spec=\(prompt.specialization.rawValue) fitness=\(String(format: "%.3f", prompt.fitness))")
        prompts.append(prompt)
    }

    public mutating func addGeneration(_ summary: GuardianGenerationSummary) {
        printFlush("Guardian Gen \(summary.generation): best_fitness=\(String(format: "%.3f", summary.bestFitness)), detection=\(String(format: "%.1f%%", summary.bestDetectionRate * 100)), fpr=\(String(format: "%.1f%%", summary.bestFalsePositiveRate * 100)), specs=\(summary.distinctSpecializations)")
        generations.append(summary)
    }

    public func promptsForGeneration(_ gen: UInt32) -> [EvolvedGuardianPrompt] {
        prompts.filter { $0.generation == gen }
    }

    public func distinctSpecializationsCount() -> Int {
        Set(prompts.map(\.specialization)).count
    }

    public func save(to path: String) throws {
        let url = URL(fileURLWithPath: path)
        let parentURL = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: parentURL, withIntermediateDirectories: true)
        let data = try JSONEncoder().encode(self)
        try data.write(to: url)
        printFlush("Guardian lineage saved to \(path)")
    }

    public static func load(from path: String) throws -> GuardianLineageStore {
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        return try JSONDecoder().decode(GuardianLineageStore.self, from: data)
    }
}
