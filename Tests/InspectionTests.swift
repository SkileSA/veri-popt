import XCTest

final class InspectionTests: XCTestCase {

    private func report(_ build: (TestDatabase) -> Void = { _ in }, user: String? = nil) throws -> Report {
        let test = try TestDatabase()
        test.createSchema()
        test.seedFromVectors()
        build(test)
        test.close()
        let db = try Database(path: test.path)
        return try Inspection(db: db, userOverride: user).run()
    }

    private func messages(_ report: Report, _ level: Report.Level) -> [String] {
        report.findings.filter { $0.level == level }.map(\.message)
    }

    func testCleanDatabasePasses() throws {
        let r = try report()
        XCTAssertFalse(r.hasFailures, r.text())
        XCTAssertTrue(messages(r, .warning).isEmpty, r.text())
        let oks = messages(r, .ok).joined(separator: "\n")
        XCTAssertTrue(oks.contains("exactly the columns SPEC § 6.1 lists"))
        XCTAssertTrue(oks.contains("every payload is an AES-GCM envelope"))
        XCTAssertTrue(oks.contains("never sync"))
        XCTAssertTrue(oks.contains("every wrapped_dek is an envelope"))
        XCTAssertTrue(oks.contains("holds a keys row, or owns, every audience"))
        XCTAssertTrue(oks.contains("own profile row is present"))
        XCTAssertTrue(r.text().contains("account: alice-uid"))
        XCTAssertTrue(r.text().contains("Result: PASS"))
    }

    func testMissingWALIsANote() throws {
        // The fixture is written without a WAL; the report says what that can mean.
        let r = try report()
        XCTAssertTrue(messages(r, .note).contains { $0.contains("no -wal file beside the copy") }, r.text())
    }

    func testExtraPlaintextColumnIsAWarning() throws {
        let r = try report { $0.exec("ALTER TABLE blocks ADD COLUMN mood TEXT;") }
        XCTAssertFalse(r.hasFailures)
        XCTAssertTrue(messages(r, .warning).contains { $0.contains("mood") }, r.text())
    }

    func testRetiredColumnsAreANoteWhenEmpty() throws {
        let empty = try report { $0.exec("ALTER TABLE blocks ADD COLUMN conflict_id TEXT;") }
        XCTAssertTrue(messages(empty, .warning).isEmpty, empty.text())
        XCTAssertTrue(messages(empty, .note).contains { $0.contains("retired column conflict_id") }, empty.text())
        let used = try report { $0.exec("ALTER TABLE blocks ADD COLUMN conflicts TEXT; UPDATE blocks SET conflicts = 'x' WHERE id = 'block-shared';") }
        XCTAssertTrue(messages(used, .warning).contains { $0.contains("conflicts with 1 non-NULL") }, used.text())
    }

    func testPlaintextPayloadFails() throws {
        let r = try report { $0.insertBlock(id: "leak", owner: "alice-uid", audience: nil, payload: "{\"payload\":{\"type\":3,\"value\":{\"text\":\"hello\"}}}") }
        XCTAssertTrue(r.hasFailures)
        XCTAssertTrue(messages(r, .fail).contains { $0.contains("not ciphertext envelopes") })
        XCTAssertTrue(r.text().contains("leak: is not an envelope"))
    }

    func testEnvelopeWithTextCiphertextFails() throws {
        let fake = try Envelope(nonce: Data(repeating: 1, count: 12), ciphertext: Data("this is readable plaintext".utf8), tag: Data(repeating: 2, count: 16)).json()
        let r = try report { $0.insertBlock(id: "fake", owner: "alice-uid", audience: nil, payload: fake) }
        XCTAssertTrue(r.text().contains("fake: has ciphertext that reads as text"), r.text())
    }

    func testUploadTriggerOnTheMirrorFails() throws {
        // The real PowerSync shape and the older direct insert both count.
        for sql in [
            "CREATE TRIGGER mirror_upload AFTER UPDATE ON plain_blocks FOR EACH ROW WHEN NOT powersync_in_sync_operation() BEGIN INSERT INTO powersync_crud(op,id,type,data) VALUES ('PATCH', NEW.id, 'plain_blocks', '{}'); END;",
            "CREATE TRIGGER mirror_upload AFTER UPDATE ON plain_blocks BEGIN INSERT INTO ps_crud(tx_id, data) VALUES (0, '{}'); END;",
        ] {
            let r = try report { $0.exec(sql) }
            XCTAssertTrue(messages(r, .fail).contains { $0.contains("plain_blocks") }, r.text())
        }
    }

    func testNoUploadTriggersAtAllIsAFailureNotAProof() throws {
        let r = try report { $0.exec("DROP TRIGGER \"blocks_UPDATE\"; DROP TRIGGER \"keys_UPDATE\"; DROP TRIGGER profiles_upload;") }
        XCTAssertTrue(messages(r, .fail).contains { $0.contains("proves nothing") }, r.text())
    }

    func testUploadQueueRules() throws {
        let personal = Vectors.string(Vectors.object("blocks", "personal"), "payload")
        let owner = Vectors.string(Vectors.object("keysRows", "ownerRow"), "wrapped_dek")
        let clean = try report {
            $0.queueUpload(op: "PATCH", table: "blocks", id: "b1", data: ["payload": personal, "revision": 2])
            $0.queueUpload(op: "PATCH", table: "blocks", id: "b1", data: ["storage": 8, "revision": 3])
            $0.queueUpload(op: "PUT", table: "keys", id: "k9", data: ["wrapped_dek": owner, "audience_id": "a", "owner_id": "o", "peer_id": "p"])
            $0.queueUpload(op: "DELETE", table: "blocks", id: "b2", data: [:])
        }
        XCTAssertFalse(clean.hasFailures, clean.text())
        XCTAssertTrue(clean.text().contains("queued operations: 4"))
        XCTAssertTrue(messages(clean, .note).contains { $0.contains("1 block patch(es) touch only plaintext columns") })

        let leaky = try report {
            $0.queueUpload(op: "PATCH", table: "blocks", id: "b1", data: ["payload": "{\"text\":\"hello\"}"])
            $0.queueUpload(op: "PATCH", table: "blocks", id: "b1", data: ["secret_note": "x"])
        }
        XCTAssertTrue(leaky.hasFailures)
        XCTAssertTrue(leaky.text().contains("payload is not an envelope"), leaky.text())
        XCTAssertTrue(leaky.text().contains("secret_note"), leaky.text())
    }

    func testAudienceCoverageForOtherAccounts() throws {
        // Bob holds a peer row for the one audience: fine.
        XCTAssertTrue(messages(try report(user: "bob-uid"), .warning).isEmpty)
        // Carol holds nothing and owns nothing: a warning naming the audience.
        let carol = try report(user: "carol-uid")
        XCTAssertTrue(messages(carol, .warning).contains { $0.contains("holds no key") }, carol.text())
        XCTAssertTrue(messages(carol, .warning).contains { $0.contains("no profile row") })
    }

    func testOwnerWithoutKeysRowIsANote() throws {
        let r = try report { $0.exec("DELETE FROM keys WHERE peer_id = 'alice-uid';") }
        XCTAssertFalse(r.hasFailures)
        XCTAssertTrue(messages(r, .note).contains { $0.contains("mint rule") }, r.text())
    }

    func testBadProfileKeyFails() throws {
        let r = try report { $0.exec("UPDATE user_profiles SET public_key = 'AAAA' WHERE id = 'bob-uid';") }
        XCTAssertTrue(messages(r, .fail).contains { $0.contains("bob-uid") }, r.text())
    }

    func testJSONRendering() throws {
        let data = try report().json()
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(object["result"] as? String, "pass")
        XCTAssertEqual((object["sections"] as? [[String: Any]])?.first?["title"] as? String, "File")
    }
}

final class DatabaseTests: XCTestCase {
    func testOpensReadOnly() throws {
        let test = try TestDatabase()
        test.createSchema()
        test.close()
        let db = try Database(path: test.path)
        XCTAssertThrowsError(try db.query("INSERT INTO local_info VALUES ('k', 'v')")) { error in
            XCTAssertTrue("\(error)".contains("readonly"), "\(error)")
        }
        XCTAssertEqual(try db.columns(of: "blocks").count, 13)
        XCTAssertEqual(try db.uploadedTables(), ["blocks", "keys", "user_profiles"])
        XCTAssertNil(try db.userId())
    }

    func testMissingOrEmptyPathIsAnError() {
        XCTAssertThrowsError(try Database(path: "/nonexistent/dir/x.sqlite")) {
            XCTAssertTrue("\($0)".contains("no such file"))
        }
        XCTAssertThrowsError(try Database(path: "")) {
            XCTAssertTrue("\($0)".contains("(empty path)"))
        }
        XCTAssertThrowsError(try Database(path: NSTemporaryDirectory()))
    }

    func testLivePathDetection() {
        XCTAssertTrue(Database.looksLive("/Users/x/Library/Containers/ABC/Data/Library/Application Support/databases/powersync-popt-it.sqlite"))
        XCTAssertFalse(Database.looksLive("/Users/x/popt-copy/powersync-popt-it.sqlite"))
    }

    func testCrudEntryParsing() {
        let entry = CrudEntry(json: "{\"op\":\"PATCH\",\"type\":\"blocks\",\"id\":\"b\",\"data\":{\"storage\":8}}")
        XCTAssertEqual(entry.op, "PATCH")
        XCTAssertEqual(entry.table, "blocks")
        XCTAssertEqual(entry.data["storage"] as? Int, 8)
        XCTAssertEqual(CrudEntry(json: "garbage").table, "?")
    }
}
