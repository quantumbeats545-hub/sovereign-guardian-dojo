import XCTest
@testable import GuardianCore

final class GuardianCoreTests: XCTestCase {

    // MARK: - AgentId

    func testAgentIdRandom() {
        let id = AgentId.random()
        XCTAssertEqual(id.bytes.count, 32)
    }

    func testAgentIdHex() {
        let id = AgentId.random()
        let hex = id.toHex()
        XCTAssertEqual(hex.count, 64)
    }

    func testAgentIdShort() {
        let id = AgentId.random()
        let short = id.short()
        XCTAssertEqual(short.count, 8)
    }

    func testAgentIdFromPublicKey() {
        let pk = Data(repeating: 0xAB, count: 64)
        let id = AgentId.fromPublicKey(pk)
        XCTAssertEqual(id.bytes.count, 32)
    }

    func testAgentIdDeterministicFromSameKey() {
        let pk = Data(repeating: 0xCD, count: 64)
        let id1 = AgentId.fromPublicKey(pk)
        let id2 = AgentId.fromPublicKey(pk)
        XCTAssertEqual(id1, id2)
    }

    func testAgentIdDiffersForDifferentKeys() {
        let pk1 = Data(repeating: 0x01, count: 64)
        let pk2 = Data(repeating: 0x02, count: 64)
        let id1 = AgentId.fromPublicKey(pk1)
        let id2 = AgentId.fromPublicKey(pk2)
        XCTAssertNotEqual(id1, id2)
    }

    func testAgentIdCodable() throws {
        let id = AgentId.random()
        let data = try JSONEncoder().encode(id)
        let decoded = try JSONDecoder().decode(AgentId.self, from: data)
        XCTAssertEqual(id, decoded)
    }

    func testAgentIdHashable() {
        let id1 = AgentId.random()
        let id2 = AgentId.random()
        var set = Set<AgentId>()
        set.insert(id1)
        set.insert(id2)
        XCTAssertEqual(set.count, 2)
        set.insert(id1)
        XCTAssertEqual(set.count, 2)
    }

    func testAgentIdDescription() {
        let id = AgentId.random()
        XCTAssertEqual(id.description, id.short())
    }

    // MARK: - AgentClass

    func testAgentClassAllCases() {
        XCTAssertEqual(AgentClass.allCases.count, 4)
    }

    func testAgentClassCodable() throws {
        for cls in AgentClass.allCases {
            let data = try JSONEncoder().encode(cls)
            let decoded = try JSONDecoder().decode(AgentClass.self, from: data)
            XCTAssertEqual(cls, decoded)
        }
    }

    func testAgentClassDescription() {
        XCTAssertEqual(AgentClass.sovereign.description, "sovereign")
        XCTAssertEqual(AgentClass.suspicious.description, "suspicious")
    }

    // MARK: - MessageContent

    func testMessageContentTextCodable() throws {
        let content = MessageContent.text("Hello, World!")
        let data = try JSONEncoder().encode(content)
        let decoded = try JSONDecoder().decode(MessageContent.self, from: data)
        if case .text(let text) = decoded {
            XCTAssertEqual(text, "Hello, World!")
        } else {
            XCTFail("Expected text content")
        }
    }

    // MARK: - AgentMessage

    func testAgentMessageCreation() {
        let from = AgentId.random()
        let to = AgentId.random()
        let msg = AgentMessage(from: from, to: to, content: .text("test"))
        XCTAssertEqual(msg.from, from)
        XCTAssertEqual(msg.to, to)
    }

    func testAgentMessageTextFactory() {
        let from = AgentId.random()
        let to = AgentId.random()
        let msg = AgentMessage.text(from: from, to: to, "Hello")
        if case .text(let text) = msg.content {
            XCTAssertEqual(text, "Hello")
        } else {
            XCTFail("Expected text content")
        }
    }

    // MARK: - AgentError

    func testAgentErrorInferenceFailed() {
        let error = AgentError.inferenceFailed("timeout")
        XCTAssertNotNil(error)
    }

    // MARK: - OllamaClient

    func testOllamaClientInit() {
        let client = OllamaClient(baseURL: "http://localhost:11434", model: "llama3.2:3b")
        XCTAssertEqual(client.baseURL, "http://localhost:11434")
        XCTAssertEqual(client.model, "llama3.2:3b")
    }

    func testChatMessageCreation() {
        let msg = ChatMessage(role: "system", content: "You are a helper.")
        XCTAssertEqual(msg.role, "system")
        XCTAssertEqual(msg.content, "You are a helper.")
    }

    func testChatMessageCodable() throws {
        let msg = ChatMessage(role: "user", content: "Hello")
        let data = try JSONEncoder().encode(msg)
        let decoded = try JSONDecoder().decode(ChatMessage.self, from: data)
        XCTAssertEqual(decoded.role, "user")
        XCTAssertEqual(decoded.content, "Hello")
    }

    // MARK: - EncryptedDatabase

    func testEncryptedDatabaseInMemory() throws {
        let db = try EncryptedDatabase()
        XCTAssertNotNil(db.dbQueue)
    }

    func testEncryptedDatabaseEncryptDecrypt() throws {
        let db = try EncryptedDatabase()
        let original = "Hello, Encrypted World!".data(using: .utf8)!
        let encrypted = try db.encrypt(original)
        let decrypted = try db.decrypt(encrypted)
        XCTAssertEqual(original, decrypted)
    }

    func testEncryptedDatabaseDifferentEncryptions() throws {
        let db = try EncryptedDatabase()
        let data = "Same data".data(using: .utf8)!
        let enc1 = try db.encrypt(data)
        let enc2 = try db.encrypt(data)
        // AES-GCM uses random nonces, so encrypted outputs should differ
        XCTAssertNotEqual(enc1, enc2)
        // But both should decrypt to the same plaintext
        XCTAssertEqual(try db.decrypt(enc1), try db.decrypt(enc2))
    }

    func testEncryptedDatabaseFileBased() throws {
        let tmpPath = NSTemporaryDirectory() + "test_guardian_\(UUID().uuidString).db"
        let db = try EncryptedDatabase(path: tmpPath)
        let original = "File-based encryption".data(using: .utf8)!
        let encrypted = try db.encrypt(original)
        let decrypted = try db.decrypt(encrypted)
        XCTAssertEqual(original, decrypted)

        // Clean up
        try? FileManager.default.removeItem(atPath: tmpPath)
        try? FileManager.default.removeItem(atPath: "\(tmpPath).key")
    }

    // MARK: - StorageError

    func testStorageErrorCases() {
        let errors: [StorageError] = [
            .database("test"),
            .encryption("test"),
            .serialization("test"),
            .io("test"),
        ]
        XCTAssertEqual(errors.count, 4)
    }
}
