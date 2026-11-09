import XCTest

final class BlocksReportTests: XCTestCase {

    private func report(_ name: String, cases: Bool, audience: String? = nil) throws -> Report {
        let test = try SessionTests.fixture()
        try test.seedMoreAudiences()
        if cases { try test.seedBlockCases() }
        test.close()
        return try BlocksReport.run(session: try SessionTests.session(name, db: try Database(path: test.path)), audience: audience)
    }

    private func totals(_ r: Report) -> String { r.sections[0].lines[0] }
    private func messages(_ r: Report, _ level: Report.Level) -> String {
        r.findings.filter { $0.level == level }.map(\.message).joined(separator: "\n")
    }
    private func problems(_ r: Report) -> String { r.sections.first { $0.title == "Problems" }?.lines.joined(separator: "\n") ?? "" }

    func testCleanDatabaseMatchesEverywhere() throws {
        let r = try report("alice", cases: false)
        XCTAssertFalse(r.hasFailures, r.text())
        XCTAssertEqual(totals(r), "blocks rows: 6; opened: 6; compared with the mirror: 6; matching: 6; pending (not yet mirrored at this revision): 0; failed: 0")
        XCTAssertTrue(messages(r, .warning).contains("1 personal row(s) belong to another account"), r.text())
        XCTAssertTrue(messages(r, .ok).contains("every block opened under the documented key"))
        XCTAssertTrue(r.sections[0].lines.contains("attachment rows: 1, each carrying a 32-byte file key"))
        XCTAssertTrue(r.sections[1].lines.contains("personal: 3 rows, 3 opened, 3 matching, 0 pending, 0 failed"), r.text())
    }

    func testEveryMirrorStateIsTold() throws {
        let r = try report("alice", cases: true)
        XCTAssertTrue(r.hasFailures)
        XCTAssertEqual(totals(r), "blocks rows: 11; opened: 10; compared with the mirror: 7; matching: 6; pending (not yet mirrored at this revision): 3; failed: 2", r.text())
        XCTAssertTrue(messages(r, .note).contains("3 row(s) are at a revision the app has not mirrored yet"))
        XCTAssertTrue(messages(r, .note).contains("1 mirror row(s) at revision -1 are deep-link seeds"))
        XCTAssertTrue(messages(r, .warning).contains("1 mirror row(s) have no blocks row") && messages(r, .warning).contains("case-orphan"))
        XCTAssertTrue(messages(r, .ok).contains("shareExtensionKey opened 1 row(s)"))
        XCTAssertTrue(problems(r).contains("case-tampered: does not open under the personal key"))
        XCTAssertTrue(problems(r).contains("case-edited: mirror differs in payload"))
        XCTAssertFalse(problems(r).contains("case-stale"))
    }

    func testAudienceFilter() throws {
        let aid = Vectors.string(Vectors.object("keysRows"), "audienceId")
        let r = try report("alice", cases: true, audience: aid)
        XCTAssertTrue(totals(r).hasPrefix("blocks rows: 1 (audience \(aid)); opened: 1; compared with the mirror: 1; matching: 1"))
    }

    func testAnotherAccountCannotOpenTheRows() throws {
        let r = try report("bob", cases: false)
        XCTAssertTrue(r.hasFailures)
        // Alice's personal rows are foreign to Bob: skipped, never tried.
        XCTAssertTrue(messages(r, .warning).contains("personal row(s) belong to another account"), r.text())
        XCTAssertFalse(problems(r).contains("block-personal"))
        XCTAssertTrue(problems(r).contains("block-bad: no key for audience aid-bad"))
        // Bob's own audience and the one Alice shared with him still open.
        XCTAssertTrue(r.sections[1].lines.contains { $0.hasPrefix("aid-bob: 1 rows, 1 opened, 1 matching") }, r.text())
    }

    func testMirrorDifferencesNameEveryField() throws {
        let plaintext = Data("{\"parentBlockId\":{\"value\":\"p\",\"updatedAt\":5},\"payload\":{\"type\":3,\"value\":{\"a\":1}},\"uiGroup\":{\"value\":6,\"updatedAt\":7}}".utf8)
        let block = try DecryptedBlock(plaintext: plaintext)
        let blocksRow = Database.Row(values: ["owner_id": .text("o"), "root_id": .text("r"), "audience_id": .null, "storage": .integer(0), "storage_updated_at": .null, "storage_key": .null])
        let same = Database.Row(values: [
            "payload": .text("{\"a\":1}"), "block_type": .integer(3), "parent_block_id": .text("p"), "parent_updated_at": .integer(5),
            "ui_group": .integer(6), "ui_group_updated_at": .integer(7), "audience_ledger": .null,
            "owner_id": .text("o"), "root_id": .text("r"), "audience_id": .null, "storage": .integer(0), "storage_updated_at": .null, "storage_key": .null,
        ])
        XCTAssertEqual(BlocksReport.differences(block: block, blocksRow: blocksRow, mirror: same), [])
        var values = same.values
        values["payload"] = .text("{\"a\":2}"); values["ui_group"] = .integer(1); values["owner_id"] = .text("x"); values["storage"] = .integer(8)
        XCTAssertEqual(BlocksReport.differences(block: block, blocksRow: blocksRow, mirror: Database.Row(values: values)), ["payload", "ui_group", "owner_id", "storage"])
    }
}
