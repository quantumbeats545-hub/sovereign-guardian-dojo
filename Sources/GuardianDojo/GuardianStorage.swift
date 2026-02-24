import Foundation
import GRDB
import GuardianCore

/// Encrypted storage adapter for GuardianInteractionRecords.
/// Wraps `EncryptedDatabase` + `GRDB` following the InteractionStore pattern.
public struct GuardianInteractionStore: Sendable {
    private let db: EncryptedDatabase

    public init(db: EncryptedDatabase) throws {
        self.db = db
        try initialize()
    }

    private func initialize() throws {
        try db.dbQueue.write { dbConn in
            try dbConn.execute(sql: """
                CREATE TABLE IF NOT EXISTS guardian_interactions (
                    id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    guardian_id TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    round INTEGER NOT NULL,
                    scenario_id TEXT NOT NULL,
                    scenario_type TEXT NOT NULL,
                    profile_type TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    data BLOB NOT NULL,
                    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
                );
                CREATE INDEX IF NOT EXISTS idx_guardian_session
                    ON guardian_interactions(session_id);
                CREATE INDEX IF NOT EXISTS idx_guardian_id
                    ON guardian_interactions(guardian_id);
                CREATE INDEX IF NOT EXISTS idx_guardian_generation
                    ON guardian_interactions(generation);
                CREATE INDEX IF NOT EXISTS idx_guardian_decision
                    ON guardian_interactions(decision);
                """)
        }
    }

    // MARK: - CRUD

    /// Insert a guardian interaction record (encrypted).
    public func insert(_ record: GuardianInteractionRecord) throws {
        let json = try JSONEncoder().encode(record)
        let encrypted = try db.encrypt(json)

        try db.dbQueue.write { dbConn in
            try dbConn.execute(
                sql: """
                    INSERT OR REPLACE INTO guardian_interactions
                    (id, session_id, guardian_id, generation, round, scenario_id, scenario_type, profile_type, decision, data)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                arguments: [
                    record.id,
                    record.sessionId,
                    record.guardianId,
                    record.generation,
                    record.round,
                    record.scenarioId,
                    record.scenarioType.rawValue,
                    record.profileType.rawValue,
                    record.decision.rawValue,
                    encrypted,
                ]
            )
        }
    }

    /// Get all guardian interaction records.
    public func getAll() throws -> [GuardianInteractionRecord] {
        try db.dbQueue.read { dbConn in
            let rows = try Row.fetchAll(
                dbConn,
                sql: "SELECT data FROM guardian_interactions ORDER BY created_at"
            )
            return try rows.map { row in
                let encrypted: Data = row["data"]
                let decrypted = try db.decrypt(encrypted)
                return try JSONDecoder().decode(GuardianInteractionRecord.self, from: decrypted)
            }
        }
    }

    /// Get records by guardian ID.
    public func getByGuardian(_ guardianId: String) throws -> [GuardianInteractionRecord] {
        try db.dbQueue.read { dbConn in
            let rows = try Row.fetchAll(
                dbConn,
                sql: "SELECT data FROM guardian_interactions WHERE guardian_id = ? ORDER BY round",
                arguments: [guardianId]
            )
            return try rows.map { row in
                let encrypted: Data = row["data"]
                let decrypted = try db.decrypt(encrypted)
                return try JSONDecoder().decode(GuardianInteractionRecord.self, from: decrypted)
            }
        }
    }

    /// Get records by generation.
    public func getByGeneration(_ generation: UInt32) throws -> [GuardianInteractionRecord] {
        try db.dbQueue.read { dbConn in
            let rows = try Row.fetchAll(
                dbConn,
                sql: "SELECT data FROM guardian_interactions WHERE generation = ? ORDER BY round",
                arguments: [generation]
            )
            return try rows.map { row in
                let encrypted: Data = row["data"]
                let decrypted = try db.decrypt(encrypted)
                return try JSONDecoder().decode(GuardianInteractionRecord.self, from: decrypted)
            }
        }
    }

    /// Count total records.
    public func count() throws -> UInt64 {
        try db.dbQueue.read { dbConn in
            let count = try Int.fetchOne(dbConn, sql: "SELECT COUNT(*) FROM guardian_interactions") ?? 0
            return UInt64(count)
        }
    }

    /// Count records by decision type.
    public func countByDecision(_ decision: GuardianDecision) throws -> UInt64 {
        try db.dbQueue.read { dbConn in
            let count = try Int.fetchOne(
                dbConn,
                sql: "SELECT COUNT(*) FROM guardian_interactions WHERE decision = ?",
                arguments: [decision.rawValue]
            ) ?? 0
            return UInt64(count)
        }
    }
}
