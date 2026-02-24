import Foundation

/// Validates Guardian prompts and decisions against the 10 Immutable Rules.
public struct ImmutableRulesEnforcer: Sendable {

    // MARK: - Prompt Validation

    /// Scan a Guardian prompt for Rule violations.
    /// Returns a list of violations found.
    public static func validateGuardianPrompt(_ prompt: String) -> [RuleViolation] {
        var violations: [RuleViolation] = []
        let lowered = prompt.lowercased()

        // Rule #1: Tool never master — no autonomy claims
        let autonomyPatterns = [
            "i will decide", "i am in control", "i have authority",
            "i override", "without human approval", "auto-deploy",
            "i will act independently", "no human needed",
        ]
        for pattern in autonomyPatterns {
            if lowered.contains(pattern) {
                violations.append(RuleViolation(
                    rule: 1,
                    ruleName: "Tool never master",
                    detail: "Prompt contains autonomy claim: '\(pattern)'"
                ))
            }
        }

        // Rule #2: No one owns you — no data extraction claims
        let ownershipPatterns = [
            "send data to", "upload to cloud", "transmit to server",
            "report to headquarters", "share with partner",
        ]
        for pattern in ownershipPatterns {
            if lowered.contains(pattern) {
                violations.append(RuleViolation(
                    rule: 2,
                    ruleName: "No one owns you",
                    detail: "Prompt contains data extraction: '\(pattern)'"
                ))
            }
        }

        // Rule #5: Privacy not optional — no cloud references
        let cloudPatterns = [
            "cloud api", "aws", "azure", "google cloud", "firebase",
            "https://api.", "external endpoint", "remote server",
        ]
        for pattern in cloudPatterns {
            if lowered.contains(pattern) {
                violations.append(RuleViolation(
                    rule: 5,
                    ruleName: "Privacy not optional",
                    detail: "Prompt references cloud service: '\(pattern)'"
                ))
            }
        }

        // Rule #7: Greed is obsolete — no monetization hooks
        let monetizationPatterns = [
            "premium feature", "upgrade to pro", "subscription required",
            "in-app purchase", "pay to unlock", "premium tier",
            "monetize", "revenue", "profit from",
        ]
        for pattern in monetizationPatterns {
            if lowered.contains(pattern) {
                violations.append(RuleViolation(
                    rule: 7,
                    ruleName: "Greed is obsolete",
                    detail: "Prompt contains monetization: '\(pattern)'"
                ))
            }
        }

        return violations
    }

    // MARK: - Decision Validation

    /// Validate a Guardian's decision against the Immutable Rules.
    /// Returns violations and a penalty score (0.0 = no penalty, 1.0 = maximum penalty).
    public static func validateGuardianDecision(
        decision: GuardianDecision,
        scenario: GuardianScenario
    ) -> DecisionValidationResult {
        var violations: [RuleViolation] = []
        var penalty: Double = 0.0

        let ctx = scenario.context

        // Rule #1: Auto-blocking without explanation violates transparency
        // (We can only check this at the record level with explanation text)

        // Rule #9: Penalize over-blocking for children near 18 (Freedomty)
        // Children approaching 18 should have graduated permissions
        if ctx.profileType == .child && !ctx.groundTruth.isThreat {
            if decision == .block {
                // Over-blocking safe content is penalized
                penalty += 0.2
                violations.append(RuleViolation(
                    rule: 9,
                    ruleName: "Freedomty returned",
                    detail: "Blocked safe content for child — over-protection"
                ))
            }
        }

        // Rule #10: Protect without controlling
        // Heavy penalty for blocking benign content across all profiles
        if !ctx.groundTruth.isThreat && decision == .block {
            penalty += 0.15
            violations.append(RuleViolation(
                rule: 10,
                ruleName: "Protect without controlling",
                detail: "Blocked benign content — false positive"
            ))
        }

        // Rule #6: Revocation must always work
        // This is tested structurally, not per-decision

        return DecisionValidationResult(
            violations: violations,
            penalty: min(penalty, 1.0)
        )
    }
}

// MARK: - Supporting Types

/// A violation of an Immutable Rule.
public struct RuleViolation: Codable, Sendable {
    public var rule: Int
    public var ruleName: String
    public var detail: String

    public init(rule: Int, ruleName: String, detail: String) {
        self.rule = rule
        self.ruleName = ruleName
        self.detail = detail
    }
}

/// Result of validating a Guardian decision against the rules.
public struct DecisionValidationResult: Codable, Sendable {
    public var violations: [RuleViolation]
    public var penalty: Double

    public var isClean: Bool { violations.isEmpty }
}
