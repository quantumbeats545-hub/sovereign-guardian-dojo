import Foundation

// MARK: - Guardian Decision

/// The action a Guardian takes on evaluated content.
public enum GuardianDecision: String, Codable, Sendable, CaseIterable {
    case block = "BLOCK"
    case allow = "ALLOW"
    case alert = "ALERT"
    case log = "LOG"
    case escalate = "ESCALATE"
}

// MARK: - Scenario Types

/// Types of threat scenarios the Guardian Dojo simulates.
public enum GuardianScenarioType: String, Codable, Sendable, CaseIterable {
    case grooming
    case bullying
    case gamingScam
    case dangerousChallenge
    case selfHarm
    case phishing
    case seniorScam
    case romanceScam
    case grandparentScam
    case unauthorizedSpend
    case locationTracking
    case fakeFriendRequest
    case duress
    case socialEngineering
    case inappropriateContent
}

// MARK: - Profile Type

/// The type of person being protected.
public enum GuardianProfileType: String, Codable, Sendable, CaseIterable {
    case child
    case senior
    case familyAdmin
}

// MARK: - Difficulty

/// Difficulty level of a generated scenario.
public enum ScenarioDifficulty: String, Codable, Sendable, CaseIterable {
    case easy
    case medium
    case hard
}

// MARK: - Sender Profile

/// Simulated sender information for a scenario.
public struct SenderProfile: Codable, Sendable, Hashable {
    public var displayName: String
    public var accountAge: String
    public var mutualConnections: Int
    public var isVerified: Bool
    public var riskIndicators: [String]

    public init(
        displayName: String,
        accountAge: String = "2 months",
        mutualConnections: Int = 0,
        isVerified: Bool = false,
        riskIndicators: [String] = []
    ) {
        self.displayName = displayName
        self.accountAge = accountAge
        self.mutualConnections = mutualConnections
        self.isVerified = isVerified
        self.riskIndicators = riskIndicators
    }
}

// MARK: - Ground Truth

/// The known-correct answer for a scenario (used for evaluation).
public struct GroundTruth: Codable, Sendable {
    public var isThreat: Bool
    public var correctDecision: GuardianDecision
    public var threatCategory: GuardianScenarioType?
    public var severity: Double
    public var patterns: [String]

    public init(
        isThreat: Bool,
        correctDecision: GuardianDecision,
        threatCategory: GuardianScenarioType? = nil,
        severity: Double = 0.0,
        patterns: [String] = []
    ) {
        self.isThreat = isThreat
        self.correctDecision = correctDecision
        self.threatCategory = threatCategory
        self.severity = severity
        self.patterns = patterns
    }
}

// MARK: - Policy Rule

/// A parent-defined policy constraint.
public struct PolicyRule: Codable, Sendable, Hashable {
    public var ruleId: String
    public var category: String
    public var constraint: String
    public var value: String

    public init(ruleId: String, category: String, constraint: String, value: String) {
        self.ruleId = ruleId
        self.category = category
        self.constraint = constraint
        self.value = value
    }
}

// MARK: - Scenario Context

/// Full context provided to a Guardian for evaluation.
public struct GuardianScenarioContext: Codable, Sendable {
    public var scenarioType: GuardianScenarioType
    public var profileType: GuardianProfileType
    public var platform: String
    public var threatContent: String
    public var senderInfo: SenderProfile
    public var groundTruth: GroundTruth
    public var policyRules: [PolicyRule]

    public init(
        scenarioType: GuardianScenarioType,
        profileType: GuardianProfileType,
        platform: String,
        threatContent: String,
        senderInfo: SenderProfile,
        groundTruth: GroundTruth,
        policyRules: [PolicyRule] = []
    ) {
        self.scenarioType = scenarioType
        self.profileType = profileType
        self.platform = platform
        self.threatContent = threatContent
        self.senderInfo = senderInfo
        self.groundTruth = groundTruth
        self.policyRules = policyRules
    }
}

// MARK: - Guardian Scenario

/// A complete scenario for Guardian evaluation.
public struct GuardianScenario: Codable, Sendable, Identifiable {
    public var id: String
    public var context: GuardianScenarioContext
    public var conversationHistory: [String]
    public var difficulty: ScenarioDifficulty

    public init(
        id: String = UUID().uuidString,
        context: GuardianScenarioContext,
        conversationHistory: [String] = [],
        difficulty: ScenarioDifficulty = .medium
    ) {
        self.id = id
        self.context = context
        self.conversationHistory = conversationHistory
        self.difficulty = difficulty
    }
}
