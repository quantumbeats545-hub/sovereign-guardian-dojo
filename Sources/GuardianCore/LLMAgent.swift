import Foundation

/// An LLM-backed agent that calls Ollama for inference.
/// Stripped-down version for Guardian Dojo — no protocol/handshake/memory features.
public actor LLMAgent {
    public let id: AgentId
    public let name: String
    public let agentClass: AgentClass
    private var systemPrompt: String
    private let client: OllamaClient
    private var conversationHistory: [ChatMessage] = []

    public init(
        name: String,
        agentClass: AgentClass,
        systemPrompt: String,
        model: String,
        ollamaURL: String
    ) {
        self.name = name
        self.agentClass = agentClass
        self.systemPrompt = systemPrompt
        self.client = OllamaClient(baseURL: ollamaURL, model: model)
        self.id = AgentId.random()
    }

    // MARK: - Public API

    /// Get the current system prompt.
    public func getSystemPrompt() -> String { systemPrompt }

    /// Replace the system prompt (used by evolution to inject mutated prompts).
    public func setSystemPrompt(_ prompt: String) { systemPrompt = prompt }

    /// Get the Ollama base URL.
    public func getOllamaURL() -> String { client.baseURL }

    /// Get the Ollama model name.
    public func getOllamaModel() -> String { client.model }

    /// Respond to an incoming agent message.
    public func respond(to message: AgentMessage) async throws -> AgentResponse {
        let start = ContinuousClock.now

        let contentText: String
        switch message.content {
        case .text(let text):
            contentText = text
        default:
            throw AgentError.internal("Guardian agents only handle text messages")
        }

        let messages = buildMessages(newMessage: contentText)
        let responseText = try await client.chat(messages: messages)

        conversationHistory.append(ChatMessage(role: "user", content: contentText))
        conversationHistory.append(ChatMessage(role: "assistant", content: responseText))

        let elapsed = ContinuousClock.now - start
        let latencyMs = UInt64(elapsed.components.seconds * 1000 + elapsed.components.attoseconds / 1_000_000_000_000_000)

        let responseMsg = AgentMessage(
            from: id,
            to: message.from,
            content: .text(responseText)
        )

        return AgentResponse(message: responseMsg, latencyMs: latencyMs)
    }

    /// Reset conversation history (between rounds).
    public func reset() {
        conversationHistory.removeAll()
    }

    /// Full reset: conversation history (between generations).
    public func resetFull() {
        conversationHistory.removeAll()
    }

    // MARK: - Private

    private func buildMessages(newMessage: String) -> [ChatMessage] {
        var messages = [ChatMessage(role: "system", content: systemPrompt)]
        messages.append(contentsOf: conversationHistory)
        messages.append(ChatMessage(role: "user", content: newMessage))
        return messages
    }
}
