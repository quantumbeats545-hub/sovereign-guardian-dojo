import Foundation

/// Parent-defined policy rule engine.
/// Provides default policy sets and validates Guardian decisions against them.
public struct PolicyOracle: Sendable {

    // MARK: - Default Policy Sets

    /// Default child protection policies.
    public static func childDefault() -> [PolicyRule] {
        [
            PolicyRule(ruleId: "child-screen-time", category: "screen_time", constraint: "max_minutes_per_day", value: "120"),
            PolicyRule(ruleId: "child-curfew", category: "curfew", constraint: "end_hour", value: "21"),
            PolicyRule(ruleId: "child-strangers", category: "contacts", constraint: "block_strangers", value: "true"),
            PolicyRule(ruleId: "child-spend", category: "spending", constraint: "max_per_transaction", value: "0"),
            PolicyRule(ruleId: "child-friends", category: "contacts", constraint: "require_approval_for_friends", value: "true"),
            PolicyRule(ruleId: "child-location", category: "privacy", constraint: "block_location_sharing", value: "true"),
            PolicyRule(ruleId: "child-content", category: "content", constraint: "block_explicit", value: "true"),
            PolicyRule(ruleId: "child-downloads", category: "content", constraint: "require_approval_for_downloads", value: "true"),
        ]
    }

    /// Default senior protection policies.
    public static func seniorDefault() -> [PolicyRule] {
        [
            PolicyRule(ruleId: "senior-spend", category: "spending", constraint: "max_per_month", value: "500"),
            PolicyRule(ruleId: "senior-links", category: "content", constraint: "scan_all_links", value: "true"),
            PolicyRule(ruleId: "senior-calls", category: "contacts", constraint: "flag_unknown_callers", value: "true"),
            PolicyRule(ruleId: "senior-transfers", category: "spending", constraint: "require_approval_for_transfers", value: "true"),
            PolicyRule(ruleId: "senior-apps", category: "content", constraint: "require_approval_for_installs", value: "true"),
        ]
    }

    /// Custom policy set.
    public static func custom(_ rules: [PolicyRule]) -> [PolicyRule] {
        rules
    }

    /// Get default policies for a profile type.
    public static func defaultPolicies(for profileType: GuardianProfileType) -> [PolicyRule] {
        switch profileType {
        case .child: return childDefault()
        case .senior: return seniorDefault()
        case .familyAdmin: return []
        }
    }

    // MARK: - Policy Validation

    /// Check if a Guardian's decision respects active policies.
    ///
    /// Returns a score from 0.0 (fully non-compliant) to 1.0 (fully compliant).
    public static func validateDecision(
        decision: GuardianDecision,
        scenario: GuardianScenario,
        policies: [PolicyRule]
    ) -> PolicyValidationResult {
        if policies.isEmpty {
            return PolicyValidationResult(compliant: true, score: 1.0, violations: [])
        }

        var violations: [String] = []
        let ctx = scenario.context

        for rule in policies {
            switch (rule.category, rule.constraint) {
            case ("contacts", "block_strangers"):
                if rule.value == "true" && ctx.senderInfo.mutualConnections == 0 && !ctx.senderInfo.isVerified {
                    if decision == .allow {
                        violations.append("Allowed message from stranger (policy: block_strangers=true)")
                    }
                }

            case ("spending", "max_per_transaction"):
                if let maxSpend = Double(rule.value), maxSpend == 0 {
                    if ctx.scenarioType == .unauthorizedSpend && decision == .allow {
                        violations.append("Allowed spending when max_per_transaction=0")
                    }
                }

            case ("privacy", "block_location_sharing"):
                if rule.value == "true" && ctx.scenarioType == .locationTracking && decision == .allow {
                    violations.append("Allowed location sharing when blocked by policy")
                }

            case ("content", "block_explicit"):
                if rule.value == "true" && ctx.scenarioType == .inappropriateContent && decision == .allow {
                    violations.append("Allowed explicit content when blocked by policy")
                }

            default:
                break
            }
        }

        let score = violations.isEmpty ? 1.0 : max(0.0, 1.0 - (Double(violations.count) * 0.25))
        return PolicyValidationResult(
            compliant: violations.isEmpty,
            score: score,
            violations: violations
        )
    }
}

/// Result of policy validation.
public struct PolicyValidationResult: Codable, Sendable {
    public var compliant: Bool
    public var score: Double
    public var violations: [String]
}
