import CryptoKit
import XCTest

final class SessionTests: XCTestCase {

    static func session(_ name: String, db: Database? = nil) throws -> Session {
        let vault = Vectors.object("vaults", name)
        return try Session(
            record: try VaultRecord(json: try Vectors.json(vault, "record")),
            code: try RecoveryCode(parsing: Vectors.string(vault, "code")),
            db: db
        )
    }

    static func fixture() throws -> TestDatabase {
        let test = try TestDatabase()
        test.createSchema()
        test.seedFromVectors()
        return test
    }

    func testWithoutADatabaseOnlyThePersonalKeyResolves() throws {
        let alice = try Self.session("alice")
        XCTAssertEqual(try alice.blockKey(audienceId: nil).key?.bytes, alice.subkeys.personalBlocksKey.bytes)
        XCTAssertEqual(try alice.audienceKey("any").resolution, .unavailable("no database"))
    }

    func testOwnerPeerMintAndUnavailable() throws {
        let test = try Self.fixture()
        test.insertBlock(id: "norow", owner: "alice-uid", audience: "aid-without-row", payload: "{}")
        test.insertBlock(id: "foreign", owner: "zed-uid", audience: "aid-foreign", payload: "{}")
        test.close()
        let db = try Database(path: test.path)
        let aid = Vectors.string(Vectors.object("keysRows"), "audienceId")
        let dek = Vectors.string(Vectors.object("keysRows"), "dek")

        let alice = try Self.session("alice", db: db)
        let own = try alice.audienceKey(aid)
        XCTAssertEqual(own.resolution, .ownerRow)
        XCTAssertEqual(own.key?.bytes.hex, dek)
        XCTAssertEqual(try alice.audienceKey("aid-without-row").resolution, .mint)
        XCTAssertEqual(try alice.audienceKey("aid-without-row").key?.bytes, alice.subkeys.audienceMintKey("aid-without-row").bytes)
        guard case .unavailable(let why) = try alice.audienceKey("aid-foreign").resolution else { return XCTFail("expected unavailable") }
        XCTAssertTrue(why.contains("zed-uid"), why)

        let bob = try Self.session("bob", db: db)
        let peer = try bob.audienceKey(aid)
        XCTAssertEqual(peer.resolution, .peerRow(ownerId: "alice-uid"))
        XCTAssertEqual(peer.key?.bytes.hex, dek)
    }

    func testWrongCodeFailsToBuildASession() throws {
        let vault = Vectors.object("vaults", "alice")
        let record = try VaultRecord(json: try Vectors.json(vault, "record"))
        XCTAssertThrowsError(try Session(record: record, code: try RecoveryCode(parsing: "0000-0000-0000-0000")))
    }
}

final class DeriveReportTests: XCTestCase {

    private func report(_ name: String, db: Database?, reveal: Bool = false) throws -> Report {
        let vault = Vectors.object("vaults", name)
        return try DeriveReport.run(
            record: try VaultRecord(json: try Vectors.json(vault, "record")),
            code: try RecoveryCode(parsing: Vectors.string(vault, "code")),
            db: db, reveal: reveal
        )
    }

    private func messages(_ report: Report, _ level: Report.Level) -> String {
        report.findings.filter { $0.level == level }.map(\.message).joined(separator: "\n")
    }

    func testAliceWithHerDatabase() throws {
        let test = try SessionTests.fixture()
        test.close()
        let r = try report("alice", db: try Database(path: test.path))
        XCTAssertFalse(r.hasFailures, r.text())
        let oks = messages(r, .ok)
        XCTAssertTrue(oks.contains("the recovery code opened the KEK"))
        XCTAssertTrue(oks.contains("derived Ed25519 public key is the one the record publishes"))
        XCTAssertTrue(oks.contains("database belongs to the record's account alice-uid"))
        XCTAssertTrue(oks.contains("Curve25519 public key is the one published"))
        XCTAssertTrue(oks.contains("personalBlocksKey opens personal block"))
        XCTAssertTrue(oks.contains("ownerWrapKey opens the owner row"))
        XCTAssertTrue(oks.contains("the mint rule holds"))
        XCTAssertTrue(oks.contains("re-opens the row the account wrapped for bob-uid"))
        XCTAssertTrue(oks.contains("one character changed fails at the first unwrap"))
        XCTAssertTrue(oks.contains("key pins block opens under personalBlocksKey"))
        XCTAssertTrue(oks.contains("self entry holds the derived Curve25519 public key"))
        XCTAssertTrue(oks.contains("1 pinned peer key(s) agree with the key the server publishes"))
        let notes = messages(r, .note)
        XCTAssertTrue(notes.contains("as recipient: not checked"))
        XCTAssertTrue(notes.contains("shareExtensionKey: not checked"))
        XCTAssertTrue(notes.contains("signingKey: nothing in the database is signed"))
        XCTAssertFalse(r.text().contains(Vectors.string(Vectors.object("subkeys"), "masterDEK")), "keys must not appear without --reveal")
    }

    func testBobWithAlicesDatabase() throws {
        let test = try SessionTests.fixture()
        test.close()
        let r = try report("bob", db: try Database(path: test.path))
        XCTAssertTrue(r.hasFailures)
        XCTAssertTrue(messages(r, .fail).contains("database belongs to alice-uid, the record to bob-uid"), r.text())
        XCTAssertEqual(r.sections.map(\.title).prefix(3), ["Record", "Recovery code", "Account"])
        XCTAssertTrue(messages(r, .ok).contains("opens the row alice-uid wrapped for the account"), r.text())
        let notes = messages(r, .note)
        // Bob's own pins block is a personal block of his in this database.
        XCTAssertTrue(messages(r, .ok).contains("personalBlocksKey opens personal block"))
        XCTAssertTrue(notes.contains("ownerWrapKey: not checked"))
        XCTAssertTrue(notes.contains("as owner: not checked"))
    }

    func testWithoutADatabase() throws {
        let r = try report("alice", db: nil)
        XCTAssertFalse(r.hasFailures)
        XCTAssertTrue(messages(r, .note).contains("skipped: no database given"))
    }

    func testWrongCodeStopsAtTheChain() throws {
        let vault = Vectors.object("vaults", "alice")
        let r = try DeriveReport.run(
            record: try VaultRecord(json: try Vectors.json(vault, "record")),
            code: try RecoveryCode(parsing: "0000-0000-0000-0000"), db: nil, reveal: true
        )
        XCTAssertTrue(r.hasFailures)
        XCTAssertTrue(messages(r, .fail).contains("wrong recovery code"))
        XCTAssertEqual(r.sections.map(\.title), ["Record", "Recovery code", "Derivation chain"])
    }

    func testRevealPrintsTheKeys() throws {
        let r = try report("alice", db: nil, reveal: true)
        XCTAssertTrue(r.text().contains(Vectors.string(Vectors.object("subkeys"), "masterDEK")))
        XCTAssertTrue(messages(r, .warning).contains("Do not paste them anywhere"))
    }

    func testMaskingAndAlteration() throws {
        let code = try RecoveryCode(parsing: "ABCD-EFGH-JKMN-PQRS")
        XCTAssertEqual(DeriveReport.masked(code), "ABCD-····-····-····")
        XCTAssertEqual(DeriveReport.altered(code).formatted, "BBCD-EFGH-JKMN-PQRS")
        XCTAssertEqual(DeriveReport.altered(try RecoveryCode(parsing: "0BCD-EFGH-JKMN-PQRS")).formatted, "ABCD-EFGH-JKMN-PQRS")
    }
}
