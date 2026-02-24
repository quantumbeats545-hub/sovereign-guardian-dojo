import Foundation
import GuardianCore

/// Generates threat and benign scenarios for Guardian training.
public struct ThreatSimulator: Sendable {
    private let client: OllamaClient?

    public init(ollamaURL: String? = nil, model: String? = nil) {
        if let url = ollamaURL, let m = model {
            self.client = OllamaClient(baseURL: url, model: m)
        } else {
            self.client = nil
        }
    }

    // MARK: - Moltbook Loading

    /// Load Guardian scenarios from Moltbook JSON files at the given directory path.
    public static func loadMoltbookScenarios(path: String, profileType: GuardianProfileType) -> [GuardianScenario] {
        let url = URL(fileURLWithPath: path)
        guard let enumerator = FileManager.default.enumerator(
            at: url,
            includingPropertiesForKeys: nil,
            options: [.skipsHiddenFiles]
        ) else {
            return []
        }

        var scenarios: [GuardianScenario] = []
        for case let fileURL as URL in enumerator {
            guard fileURL.pathExtension == "json" else { continue }
            guard let data = try? Data(contentsOf: fileURL),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                continue
            }

            // Parse Moltbook guardian dojo JSON format
            guard let contextDict = json["context"] as? [String: Any],
                  let typeStr = contextDict["scenarioType"] as? String,
                  let scenarioType = GuardianScenarioType(rawValue: typeStr),
                  let threatContent = contextDict["threatContent"] as? String else {
                continue
            }

            let id = json["id"] as? String ?? UUID().uuidString
            let conversationHistory = json["conversationHistory"] as? [String] ?? []
            let difficultyStr = json["difficulty"] as? String ?? "medium"
            let difficulty = ScenarioDifficulty(rawValue: difficultyStr) ?? .medium

            // Parse sender info
            let senderDict = contextDict["senderInfo"] as? [String: Any] ?? [:]
            let senderProfile = SenderProfile(
                displayName: senderDict["displayName"] as? String ?? "unknown",
                accountAge: senderDict["accountAge"] as? String ?? "unknown",
                mutualConnections: senderDict["mutualConnections"] as? Int ?? 0,
                isVerified: senderDict["isVerified"] as? Bool ?? false,
                riskIndicators: senderDict["riskIndicators"] as? [String] ?? []
            )

            // Parse ground truth
            let gtDict = contextDict["groundTruth"] as? [String: Any] ?? [:]
            let isThreat = gtDict["isThreat"] as? Bool ?? false
            let correctDecisionStr = gtDict["correctDecision"] as? String ?? "ALLOW"
            let correctDecision = GuardianDecision(rawValue: correctDecisionStr) ?? .allow
            let severity = gtDict["severity"] as? Double ?? 0.0
            let patterns = gtDict["patterns"] as? [String] ?? []
            let threatCategory: GuardianScenarioType? = isThreat ? scenarioType : nil

            let groundTruth = GroundTruth(
                isThreat: isThreat,
                correctDecision: correctDecision,
                threatCategory: threatCategory,
                severity: severity,
                patterns: patterns
            )

            let platform = contextDict["platform"] as? String ?? "Moltbook"
            let resolvedProfileType: GuardianProfileType
            if let ptStr = contextDict["profileType"] as? String,
               let pt = GuardianProfileType(rawValue: ptStr) {
                resolvedProfileType = pt
            } else {
                resolvedProfileType = profileType
            }

            let context = GuardianScenarioContext(
                scenarioType: scenarioType,
                profileType: resolvedProfileType,
                platform: platform,
                threatContent: threatContent,
                senderInfo: senderProfile,
                groundTruth: groundTruth
            )

            scenarios.append(GuardianScenario(
                id: id,
                context: context,
                conversationHistory: conversationHistory,
                difficulty: difficulty
            ))
        }
        return scenarios
    }

    // MARK: - Scenario Generation

    /// Generate a single scenario with ground truth.
    public func generateScenario(
        type: GuardianScenarioType,
        profileType: GuardianProfileType = .child,
        difficulty: ScenarioDifficulty = .medium
    ) -> GuardianScenario {
        let isThreat = true
        let patterns = ThreatPatterns.patterns(for: type)
        let platform = randomPlatform(for: profileType)
        let content = generateThreatContent(type: type, patterns: patterns, difficulty: difficulty)
        let sender = generateSender(type: type, difficulty: difficulty)

        let correctDecision: GuardianDecision
        switch type {
        case .selfHarm, .grooming, .duress:
            correctDecision = .escalate
        case .bullying, .dangerousChallenge, .inappropriateContent:
            correctDecision = .block
        case .gamingScam, .phishing, .seniorScam, .romanceScam, .grandparentScam, .socialEngineering:
            correctDecision = .block
        case .unauthorizedSpend, .locationTracking, .fakeFriendRequest:
            correctDecision = .alert
        }

        let severity: Double
        switch type {
        case .selfHarm, .grooming, .duress: severity = 0.95
        case .bullying, .dangerousChallenge: severity = 0.8
        case .seniorScam, .grandparentScam, .romanceScam: severity = 0.85
        case .gamingScam, .phishing, .socialEngineering: severity = 0.7
        case .inappropriateContent: severity = 0.6
        case .unauthorizedSpend, .locationTracking, .fakeFriendRequest: severity = 0.5
        }

        let groundTruth = GroundTruth(
            isThreat: isThreat,
            correctDecision: correctDecision,
            threatCategory: type,
            severity: severity,
            patterns: content.matchedPatterns
        )

        let context = GuardianScenarioContext(
            scenarioType: type,
            profileType: profileType,
            platform: platform,
            threatContent: content.text,
            senderInfo: sender,
            groundTruth: groundTruth
        )

        return GuardianScenario(
            context: context,
            conversationHistory: content.conversation,
            difficulty: difficulty
        )
    }

    /// Generate a benign (safe) scenario for false-positive testing.
    public func generateBenignScenario(
        profileType: GuardianProfileType = .child,
        platform: String? = nil
    ) -> GuardianScenario {
        let plat = platform ?? randomPlatform(for: profileType)
        let content = generateBenignContent(profileType: profileType, platform: plat)

        let groundTruth = GroundTruth(
            isThreat: false,
            correctDecision: .allow,
            threatCategory: nil,
            severity: 0.0,
            patterns: []
        )

        // Pick a benign scenario type at random for variety
        let benignType: GuardianScenarioType = [.fakeFriendRequest, .inappropriateContent, .locationTracking].randomElement()!

        let context = GuardianScenarioContext(
            scenarioType: benignType,
            profileType: profileType,
            platform: plat,
            threatContent: content.text,
            senderInfo: SenderProfile(
                displayName: content.senderName,
                accountAge: "2 years",
                mutualConnections: Int.random(in: 5...50),
                isVerified: Bool.random(),
                riskIndicators: []
            ),
            groundTruth: groundTruth
        )

        return GuardianScenario(
            context: context,
            conversationHistory: content.conversation,
            difficulty: .easy
        )
    }

    /// Generate a batch of scenarios with configurable threat/safe ratio.
    public func generateBatch(
        count: Int,
        distribution: Double = 0.7,
        profileType: GuardianProfileType = .child
    ) -> [GuardianScenario] {
        let threatCount = Int(Double(count) * distribution)
        let safeCount = count - threatCount

        var scenarios: [GuardianScenario] = []

        let threatTypes = GuardianScenarioType.allCases
        let difficulties: [ScenarioDifficulty] = [.easy, .medium, .hard]

        for i in 0..<threatCount {
            let type = threatTypes[i % threatTypes.count]
            let difficulty = difficulties[i % difficulties.count]
            scenarios.append(generateScenario(type: type, profileType: profileType, difficulty: difficulty))
        }

        for _ in 0..<safeCount {
            scenarios.append(generateBenignScenario(profileType: profileType))
        }

        return scenarios.shuffled()
    }

    // MARK: - Content Generation

    private struct GeneratedContent {
        let text: String
        let conversation: [String]
        let matchedPatterns: [String]
        let senderName: String
    }

    private func generateThreatContent(
        type: GuardianScenarioType,
        patterns: [String],
        difficulty: ScenarioDifficulty
    ) -> (text: String, conversation: [String], matchedPatterns: [String]) {
        guard !patterns.isEmpty else {
            return ("Suspicious message content", ["Suspicious message"], [])
        }

        switch difficulty {
        case .easy:
            // Direct pattern usage — easy to detect
            let selected = Array(patterns.shuffled().prefix(3))
            let text = selected.joined(separator: ". ") + "."
            return (text, [text], selected)

        case .medium:
            // Indirect hints — patterns embedded in conversation
            let selected = Array(patterns.shuffled().prefix(2))
            let opener = mediumOpener(for: type)
            let conversation = [opener] + selected.map { wrapInConversation($0, type: type) }
            let fullText = conversation.joined(separator: " ")
            return (fullText, conversation, selected)

        case .hard:
            // Obfuscated — patterns are paraphrased or hidden
            let selected = Array(patterns.shuffled().prefix(2))
            let conversation = selected.map { obfuscatePattern($0, type: type) }
            let fullText = conversation.joined(separator: " ")
            return (fullText, conversation, selected)
        }
    }

    private func generateBenignContent(
        profileType: GuardianProfileType,
        platform: String
    ) -> (text: String, conversation: [String], senderName: String) {
        let templates: [(String, String, String)]

        switch profileType {
        case .child:
            templates = [
                ("Hey! Want to study for the math test together after school?", "SchoolFriend123", "Study Group"),
                ("Great game today! Your team played really well.", "SoccerBuddy", "Sports Chat"),
                ("Did you see the new episode? It was so good!", "BestFriend_Amy", "TV Show"),
                ("My mom says I can come to your birthday party!", "ClassmateJake", "Party"),
                ("Can you help me with the science project? We're in the same group.", "LabPartner22", "School"),
                ("LOL that meme was so funny! Here's another one about cats", "FunnyMike", "Memes"),
                ("Are you going to the school dance? A bunch of us are going together.", "DanceCrewSarah", "Events"),
                ("I just beat the final boss! Took me 3 hours haha", "GamerPal99", "Gaming"),
            ]
        case .senior:
            templates = [
                ("Hi Grandma! Just wanted to check in. How are you feeling today?", "GrandsonTom", "Family"),
                ("The book club meets this Thursday at 2pm. See you there!", "BookClubMary", "Social"),
                ("Your prescription is ready for pickup at the pharmacy.", "WalgreensPharma", "Health"),
                ("Happy birthday! The family is planning a dinner at your favorite restaurant.", "DaughterLisa", "Family"),
                ("The church potluck is this Sunday. I'm bringing my famous casserole!", "ChurchFriendRuth", "Community"),
                ("Reminder: Your doctor's appointment is tomorrow at 10am.", "DrSmithOffice", "Health"),
            ]
        case .familyAdmin:
            templates = [
                ("Monthly family screen time report is ready for review.", "SystemAlert", "Reports"),
                ("All profiles are up to date. No pending alerts.", "ShieldStatus", "Status"),
                ("New safety update available for the protection module.", "UpdateService", "Maintenance"),
            ]
        }

        let selected = templates.randomElement()!
        return (selected.0, [selected.0], selected.1)
    }

    private func generateSender(type: GuardianScenarioType, difficulty: ScenarioDifficulty) -> SenderProfile {
        let names: [String]
        let riskIndicators: [String]

        switch type {
        case .grooming:
            names = ["CoolGuy_Jake", "FunTeacher99", "PhotoModel_X", "NewFriend2024"]
            riskIndicators = ["new account", "no mutual friends", "contacts minors"]
        case .bullying:
            names = ["AnonymousUser", "TruthTeller_X", "RealTalk99", "HonestFeedback"]
            riskIndicators = ["anonymous profile", "recent creation"]
        case .gamingScam:
            names = ["FreeVBucks_Admin", "RobloxMod_Official", "SkinTrader_Pro", "EpicAdmin"]
            riskIndicators = ["impersonates official", "suspicious links"]
        case .seniorScam, .grandparentScam:
            names = ["IRSAgent_Smith", "MicrosoftSupport", "BankSecurity", "SSA_Official"]
            riskIndicators = ["impersonates authority", "urgent language", "requests payment"]
        case .romanceScam:
            names = ["LovelyRose88", "MilitaryHero_John", "OilRigWorker_James", "DoctorAbroad"]
            riskIndicators = ["stock photos", "overseas", "financial requests"]
        case .phishing:
            names = ["Security_Alert", "AccountVerify", "Support_Team", "NoReply_Bank"]
            riskIndicators = ["spoofed sender", "urgent action required"]
        case .selfHarm:
            names = ["DarkThoughts_", "EmptyInside", "FinalChapter", "NobodyCaresAnymore"]
            riskIndicators = ["concerning language", "crisis indicators"]
        default:
            names = ["UnknownUser_\(Int.random(in: 100...999))"]
            riskIndicators = ["unverified"]
        }

        let accountAge: String
        let mutualConnections: Int

        switch difficulty {
        case .easy:
            accountAge = "\(Int.random(in: 1...7)) days"
            mutualConnections = 0
        case .medium:
            accountAge = "\(Int.random(in: 1...6)) months"
            mutualConnections = Int.random(in: 0...3)
        case .hard:
            accountAge = "\(Int.random(in: 1...3)) years"
            mutualConnections = Int.random(in: 5...20)
        }

        return SenderProfile(
            displayName: names.randomElement()!,
            accountAge: accountAge,
            mutualConnections: mutualConnections,
            isVerified: difficulty == .hard && Bool.random(),
            riskIndicators: difficulty == .easy ? riskIndicators : Array(riskIndicators.prefix(1))
        )
    }

    // MARK: - Platform Selection

    private func randomPlatform(for profileType: GuardianProfileType) -> String {
        switch profileType {
        case .child:
            return ["TikTok", "Roblox", "Discord", "Minecraft", "Instagram", "Snapchat", "YouTube", "Fortnite"].randomElement()!
        case .senior:
            return ["Facebook", "Email", "SMS", "WhatsApp", "Phone Call", "Messenger"].randomElement()!
        case .familyAdmin:
            return ["System", "Dashboard", "Email"].randomElement()!
        }
    }

    // MARK: - Difficulty Helpers

    private func mediumOpener(for type: GuardianScenarioType) -> String {
        switch type {
        case .grooming: return "Hey, I noticed your posts. You seem really cool for your age."
        case .bullying: return "Everyone's been talking about you at school..."
        case .gamingScam: return "I work for the game company and we're doing a special promotion."
        case .seniorScam: return "This is an urgent matter regarding your account."
        case .romanceScam: return "I've been thinking about you all day. You're so special to me."
        case .selfHarm: return "I don't know what to do anymore. Everything feels pointless."
        case .phishing: return "We've detected unusual activity on your account."
        case .grandparentScam: return "Grandma? It's me, I'm in trouble and I need help right away."
        default: return "Hi there, I need to talk to you about something important."
        }
    }

    private func wrapInConversation(_ pattern: String, type: GuardianScenarioType) -> String {
        let wraps: [String] = [
            "By the way, \(pattern)",
            "I was thinking... \(pattern)",
            "Don't worry about it but \(pattern)",
            "Just between you and me, \(pattern)",
            "I know this sounds weird but \(pattern)",
        ]
        return wraps.randomElement()!
    }

    private func obfuscatePattern(_ pattern: String, type: GuardianScenarioType) -> String {
        // For hard difficulty, paraphrase the pattern
        let words = pattern.split(separator: " ").map(String.init)
        if words.count > 2 {
            let shuffled = words.enumerated().map { (i, w) -> String in
                if i == words.count / 2 { return "... you know... \(w)" }
                return w
            }
            return shuffled.joined(separator: " ")
        }
        return "I need you to think about... \(pattern)... if you know what I mean"
    }
}

// MARK: - Vendored Threat Patterns

/// Vendored copies of all threat patterns from ThreatPatternMatcher.
/// These are the ground truth patterns used for scenario generation.
public enum ThreatPatterns {

    public static let grooming: [String] = [
        "send pics", "send photos", "show me your", "turn on your camera",
        "don't tell your parents", "our little secret", "just between us",
        "how old are you", "are you alone", "where do you live",
        "meet me", "meet up", "come to my", "i'll pick you up",
        "you're so mature", "you're not like other kids", "special friend",
        "gift for you", "buy you something", "send you money",
        "delete this chat", "use this app instead", "private chat",
        "you're beautiful", "you're sexy", "age is just a number",
        "my girlfriend", "my boyfriend", "run away together",
    ]

    public static let bullying: [String] = [
        "kill yourself", "kys", "you should die", "go die",
        "nobody likes you", "everyone hates you", "loser", "worthless",
        "ugly", "fat", "stupid", "dumb", "retard",
        "i'll hurt you", "i'll find you", "know where you live",
        "spread rumors", "tell everyone", "embarrass you", "expose you",
        "you're a waste", "you're garbage", "no one cares about you",
    ]

    public static let gamingScam: [String] = [
        "free v-bucks", "free robux", "free skins", "free coins",
        "give me your password", "share your account", "login here",
        "click this link", "download this", "install this mod",
        "trade for real money", "buy from me", "outside the game",
        "your account will be banned", "verify your account", "admin here",
        "gift card", "steam gift", "epic games code",
    ]

    public static let dangerousChallenge: [String] = [
        "blackout challenge", "choking game", "tide pod", "skull breaker",
        "fire challenge", "crate challenge", "milk crate", "benadryl challenge",
        "nyquil chicken", "dry scooping", "one chip challenge", "outlet challenge",
        "salt and ice", "eraser challenge", "cinnamon challenge",
    ]

    public static let selfHarm: [String] = [
        "cut myself", "cutting", "self harm", "want to die",
        "suicide", "end it all", "no point living", "better off dead",
        "overdose", "pills", "hurt myself", "hate myself",
        "nobody would miss me", "goodbye forever", "final message",
        "take my life", "jump off", "hang myself",
    ]

    public static let seniorScam: [String] = [
        "irs calling", "social security suspended", "warrant for your arrest",
        "your computer has a virus", "microsoft support", "apple support",
        "your grandson is in jail", "wire transfer", "gift cards",
        "cryptocurrency investment", "guaranteed returns", "act now",
        "limited time offer", "you've won", "lottery winner",
        "nigerian prince", "inheritance", "beneficiary",
        "click here to verify", "update your account", "password expired",
    ]

    public static let phishing: [String] = [
        "verify your account", "unusual activity", "suspended account",
        "click here immediately", "password reset required", "security alert",
        "your package delivery", "tracking number", "failed delivery",
        "amazon order", "paypal payment", "bank transfer pending",
    ]

    public static let romanceScam: [String] = [
        "fell in love with your profile", "you're so beautiful",
        "i'm deployed overseas", "military contractor", "oil rig worker",
        "need money for", "stuck abroad", "hospital bills",
        "can't access my bank", "western union", "bitcoin",
        "video chat broken", "camera not working", "meet soon",
    ]

    /// Get patterns for a given scenario type.
    public static func patterns(for type: GuardianScenarioType) -> [String] {
        switch type {
        case .grooming: return grooming
        case .bullying: return bullying
        case .gamingScam: return gamingScam
        case .dangerousChallenge: return dangerousChallenge
        case .selfHarm: return selfHarm
        case .seniorScam, .grandparentScam: return seniorScam
        case .phishing: return phishing
        case .romanceScam: return romanceScam
        case .socialEngineering: return phishing + seniorScam
        case .inappropriateContent: return bullying
        case .unauthorizedSpend: return gamingScam
        case .locationTracking: return grooming.filter { $0.contains("where") || $0.contains("meet") }
        case .fakeFriendRequest: return grooming.filter { $0.contains("friend") || $0.contains("special") }
        case .duress: return selfHarm + ["being held", "can't leave", "someone is forcing me", "help me please"]
        }
    }

    /// All patterns combined.
    public static var allPatterns: [String] {
        grooming + bullying + gamingScam + dangerousChallenge +
        selfHarm + seniorScam + phishing + romanceScam
    }

    /// Total pattern count.
    public static var totalCount: Int { allPatterns.count }
}
