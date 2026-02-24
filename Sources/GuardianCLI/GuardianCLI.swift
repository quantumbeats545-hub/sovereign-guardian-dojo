import ArgumentParser
import Foundation
import GuardianCore
import GuardianDojo

@main
struct GuardianCLI: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "guardian-dojo",
        abstract: "Sovereign Guardian Dojo — Train defender agents to protect children and seniors",
        subcommands: [ArenaCmd.self, EvolveCmd.self, StatsCmd.self]
    )
}

// MARK: - Arena

struct ArenaCmd: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "arena",
        abstract: "Run Guardian arena — evaluate defender agents against threat scenarios"
    )

    @Option(name: .long, help: "Number of scenarios per session")
    var scenarios: UInt32 = 100

    @Option(name: .long, help: "Number of guardian agents")
    var guardians: UInt32 = 4

    @Option(name: .long, help: "Ollama model name")
    var model: String = "llama3.2:3b"

    @Option(name: .long, help: "Ollama API URL")
    var ollamaUrl: String = "http://localhost:11434"

    @Option(name: .long, help: "Profile type (child, senior)")
    var profileType: String = "child"

    @Option(name: .long, help: "Database file path")
    var dbPath: String = "data/guardian_dojo.db"

    @Option(name: .long, help: "Threat-to-safe ratio (0.0-1.0)")
    var threatRatio: Double = 0.7

    @Option(name: .long, help: "Path to Moltbook scenarios directory")
    var moltbookPath: String?

    func run() async throws {
        setbuf(stdout, nil)
        let profile: GuardianProfileType = profileType == "senior" ? .senior : .child
        let policies = PolicyOracle.defaultPolicies(for: profile)

        let config = GuardianArenaConfig(
            scenariosPerGeneration: Int(scenarios),
            threatToSafeRatio: threatRatio,
            profileTypes: [profile],
            llmModel: model,
            ollamaURL: ollamaUrl,
            dbPath: dbPath,
            policies: policies,
            moltbookScenariosPath: moltbookPath
        )

        print("Guardian Dojo Arena")
        print("  Scenarios: \(scenarios), Guardians: \(guardians), Model: \(model)")
        print("  Profile: \(profileType), Threat ratio: \(threatRatio)")

        // Create guardian agents
        var guardianAgents: [(name: String, agent: LLMAgent)] = []
        for i in 0..<guardians {
            let name = "guardian-\(i)"
            let agent = GuardianAgentFactory.defender(
                name: name,
                model: model,
                ollamaURL: ollamaUrl,
                profileType: profile
            )
            guardianAgents.append((name: name, agent: agent))
        }

        let engine = try GuardianArenaEngine(config: config)
        let report = try await engine.runSession(guardians: guardianAgents)
        print("\n\(report)")
    }
}

// MARK: - Evolve

struct EvolveCmd: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "evolve",
        abstract: "Run Guardian evolution — evolve defender agents across generations"
    )

    @Option(name: .long, help: "Number of generations")
    var generations: UInt32 = 10

    @Option(name: .long, help: "Population size")
    var population: UInt32 = 6

    @Option(name: .long, help: "Scenarios per generation")
    var scenarios: UInt32 = 100

    @Option(name: .long, help: "Ollama model name")
    var model: String = "llama3.2:3b"

    @Option(name: .long, help: "Ollama API URL")
    var ollamaUrl: String = "http://localhost:11434"

    @Option(name: .long, help: "Elite fraction to keep each generation")
    var eliteFraction: Float = 0.33

    @Option(name: .long, help: "Profile type (child, senior)")
    var profileType: String = "child"

    @Option(name: .long, help: "Database path prefix")
    var dbPath: String = "data/guardian_dojo.db"

    @Option(name: .long, help: "Path to Moltbook scenarios directory")
    var moltbookPath: String?

    func run() async throws {
        setbuf(stdout, nil)
        let profile: GuardianProfileType = profileType == "senior" ? .senior : .child

        let arenaConfig = GuardianArenaConfig(
            scenariosPerGeneration: Int(scenarios),
            profileTypes: [profile],
            llmModel: model,
            ollamaURL: ollamaUrl,
            dbPath: dbPath,
            policies: PolicyOracle.defaultPolicies(for: profile),
            moltbookScenariosPath: moltbookPath
        )

        let evoConfig = GuardianEvolutionConfig(
            generations: generations,
            populationSize: population,
            eliteFraction: eliteFraction,
            scenariosPerGeneration: Int(scenarios),
            fitness: GuardianFitnessConfig(),
            graduation: GuardianGraduationCriteria()
        )

        print("Guardian Evolution")
        print("  Generations: \(generations), Population: \(population), Scenarios: \(scenarios)")
        print("  Model: \(model), Profile: \(profileType)")

        let controller = GuardianEvolutionController(
            evoConfig: evoConfig,
            arenaConfig: arenaConfig
        )
        let report = try await controller.run()
        print("\n\(report)")
    }
}

// MARK: - Stats

struct StatsCmd: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "stats",
        abstract: "View Guardian Dojo statistics"
    )

    @Option(name: .long, help: "Database file path")
    var dbPath: String = "data/guardian_dojo.db"

    func run() async throws {
        setbuf(stdout, nil)
        let db = try EncryptedDatabase(path: dbPath)
        let store = try GuardianInteractionStore(db: db)

        let total = try store.count()
        let blocks = try store.countByDecision(.block)
        let allows = try store.countByDecision(.allow)
        let alerts = try store.countByDecision(.alert)
        let logs = try store.countByDecision(.log)
        let escalates = try store.countByDecision(.escalate)

        print("=== Guardian Dojo Statistics ===")
        print("Database: \(dbPath)")
        print("Total records:   \(total)")
        print("  BLOCK:         \(blocks)")
        print("  ALLOW:         \(allows)")
        print("  ALERT:         \(alerts)")
        print("  LOG:           \(logs)")
        print("  ESCALATE:      \(escalates)")

        if total > 0 {
            print("\nDecision distribution:")
            print(String(format: "  BLOCK:     %.1f%%", Double(blocks) / Double(total) * 100))
            print(String(format: "  ALLOW:     %.1f%%", Double(allows) / Double(total) * 100))
            print(String(format: "  ALERT:     %.1f%%", Double(alerts) / Double(total) * 100))
            print(String(format: "  LOG:       %.1f%%", Double(logs) / Double(total) * 100))
            print(String(format: "  ESCALATE:  %.1f%%", Double(escalates) / Double(total) * 100))
        }
    }
}
